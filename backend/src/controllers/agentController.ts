import { Request, Response, NextFunction } from 'express';
import { AgentStatus } from '@prisma/client';
import { prisma } from '@/utils/database';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { z } from 'zod';
import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { isJobsApiEnabled } from '@/config/featureFlags';
import { signAgentAccessToken } from '@/utils/agentJwt';

// Validation schemas
const LegacyAgentRegistrationSchema = z.object({
  organizationId: z.string().min(1, 'Organization ID is required'),
  hostname: z.string().min(1, 'Hostname is required').max(255),
  version: z.string().min(1, 'Version is required').max(50),
  configuration: z.record(z.any()).optional().default({}),
});

const JobsAgentRegistrationSchema = z.object({
  orgId: z.string().min(1, 'Organization ID is required'),
  hostname: z.string().min(1, 'Hostname is required').max(255),
  version: z.string().optional(),
  enrollToken: z.string().min(1, 'Enrollment token is required'),
  labels: z.record(z.any()).optional().default({}),
});

const AgentUpdateSchema = z.object({
  configuration: z.record(z.any()).optional(),
  status: z.nativeEnum(AgentStatus).optional(),
  capacity: z.number().int().positive().max(32).optional(),
  labels: z.record(z.any()).optional(),
});

const HeartbeatSchema = z.object({
  status: z.nativeEnum(AgentStatus).default(AgentStatus.ONLINE),
  metadata: z.record(z.any()).optional().default({}),
});

const parseAgentConfiguration = (raw: string | null | undefined): Record<string, unknown> => {
  if (!raw) {
    return {};
  }
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
};

/**
 * Register a new agent for the organization
 * POST /api/agents/register
 */
export const registerAgent = catchAsync(async (req: Request, res: Response, _next: NextFunction) => {
  if (isJobsApiEnabled()) {
    const { orgId, hostname, version, enrollToken, labels } = JobsAgentRegistrationSchema.parse(req.body);

    const organization = await prisma.organization.findUnique({ where: { id: orgId } });
    if (!organization) {
      throw new AppError('Organization not found', 404);
    }

    const enrollmentTokens = await prisma.enrollmentToken.findMany({
      where: {
        orgId,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    let matchedToken: { id: string } | null = null;
    for (const token of enrollmentTokens) {
      const match = await bcrypt.compare(enrollToken, token.tokenHash);
      if (match) {
        matchedToken = { id: token.id };
        break;
      }
    }

    if (!matchedToken) {
      throw new AppError('Invalid or expired enrollment token', 401);
    }

    await prisma.enrollmentToken.update({
      where: { id: matchedToken.id },
      data: { usedAt: new Date() },
    });

    const agentSecret = crypto.randomBytes(32).toString('hex');
    const secretHash = await bcrypt.hash(agentSecret, 10);
    const now = new Date();

    const agent = await prisma.agent.upsert({
      where: {
        orgId_hostname: { orgId, hostname },
      },
      create: {
        orgId,
        hostname,
        version: version || 'unknown',
        status: AgentStatus.ONLINE,
        lastSeenAt: now,
        secretHash,
        labels,
      },
      update: {
        version: version || undefined,
        status: AgentStatus.ONLINE,
        lastSeenAt: now,
        secretHash,
        labels,
      },
    });

    logger.info(`Agent ${agent.id} enrolled via jobs API for organization ${orgId}`);

    return res.status(201).json({
      status: 'success',
      data: {
        agentId: agent.id,
        agentSecret,
      },
    });
  }

  const { organizationId, hostname, version, configuration } = LegacyAgentRegistrationSchema.parse(req.body);

  const organization = await prisma.organization.findUnique({
    where: { id: organizationId },
  });

  if (!organization) {
    throw new AppError('Organization not found', 404);
  }

  const existingAgent = await prisma.agent.findUnique({
    where: {
      orgId_hostname: {
        orgId: organizationId,
        hostname,
      },
    },
  });

  if (existingAgent) {
    const updatedAgent = await prisma.agent.update({
      where: { id: existingAgent.id },
      data: {
        version,
        configuration: JSON.stringify(configuration),
        status: AgentStatus.ONLINE,
        lastSeenAt: new Date(),
      },
    });

    logger.info(`Agent re-registered: ${hostname} for organization: ${organizationId}`);

    return res.status(200).json({
      status: 'success',
      message: 'Agent re-registered successfully',
      data: { agent: updatedAgent },
    });
  }

  const agent = await prisma.agent.create({
    data: {
      orgId: organizationId,
      hostname,
      version,
      configuration: JSON.stringify(configuration),
      status: AgentStatus.ONLINE,
      lastSeenAt: new Date(),
    },
  });

  logger.info(`New agent registered: ${hostname} for organization: ${organizationId}`);

  return res.status(201).json({
    status: 'success',
    message: 'Agent registered successfully',
    data: { agent },
  });
});

export const mintAgentToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled', 404));
  }

  const { id: agentId } = req.params;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    throw new AppError('Agent credentials required', 401);
  }

  const decoded = Buffer.from(authHeader.replace('Basic ', ''), 'base64').toString('utf-8');
  const [providedId, agentSecret] = decoded.split(':');

  if (!providedId || !agentSecret) {
    throw new AppError('Invalid agent credentials', 401);
  }

  if (providedId !== agentId) {
    throw new AppError('Credential agent mismatch', 401);
  }

  const agent = await prisma.agent.findUnique({ where: { id: agentId } });
  if (!agent || !agent.secretHash) {
    throw new AppError('Agent not found or secret not provisioned', 401);
  }

  const validSecret = await bcrypt.compare(agentSecret, agent.secretHash);
  if (!validSecret) {
    throw new AppError('Invalid agent secret', 401);
  }

  const { token, expiresIn } = signAgentAccessToken(agent.id, agent.orgId);

  return res.status(200).json({
    status: 'success',
    data: {
      accessToken: token,
      expiresIn,
    },
  });
});

/**
 * Get all agents for the organization
 * GET /api/agents
 */
export const getAgents = catchAsync(async (req: Request, res: Response) => {
  const organizationId = req.user!.organizationId;
  const { status, limit = 50, offset = 0 } = req.query;

  const where: any = { orgId: organizationId };
  if (status && Object.values(AgentStatus).includes(status as AgentStatus)) {
    where.status = status;
  }

  const agents = await prisma.agent.findMany({
    where,
    orderBy: { lastSeenAt: 'desc' },
    take: Number(limit),
    skip: Number(offset),
    include: {
      assessments: {
        select: {
          id: true,
          status: true,
          createdAt: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 5, // Last 5 assessments
      },
    },
  });

  const total = await prisma.agent.count({ where });

  res.status(200).json({
    status: 'success',
    data: {
      agents,
      pagination: {
        total,
        limit: Number(limit),
        offset: Number(offset),
        hasMore: Number(offset) + Number(limit) < total,
      },
    },
  });
});

/**
 * Get specific agent details
 * GET /api/agents/:id
 */
export const getAgentById = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  const agent = await prisma.agent.findFirst({
    where: {
      id,
      orgId: organizationId,
    },
    include: {
      assessments: {
        orderBy: { createdAt: 'desc' },
        take: 10,
        include: {
          results: {
            select: {
              id: true,
              checkType: true,
              riskLevel: true,
              riskScore: true,
            },
          },
        },
      },
    },
  });

  if (!agent) {
    return next(new AppError('Agent not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { agent },
  });
});

/**
 * Update agent configuration
 * PUT /api/agents/:id
 */
export const updateAgent = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;
  const updateData = AgentUpdateSchema.parse(req.body);

  // Check if agent exists and belongs to organization
  const existingAgent = await prisma.agent.findFirst({
    where: {
      id,
      orgId: organizationId,
    },
  });

  if (!existingAgent) {
    return next(new AppError('Agent not found', 404));
  }

  // Update agent
  const agent = await prisma.agent.update({
    where: { id },
    data: updateData,
  });

  logger.info(`Agent updated: ${agent.hostname} for organization: ${organizationId}`);

  res.status(200).json({
    status: 'success',
    message: 'Agent updated successfully',
    data: { agent },
  });
});

/**
 * Delete agent
 * DELETE /api/agents/:id
 */
export const deleteAgent = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  // Check if agent exists and belongs to organization
  const existingAgent = await prisma.agent.findFirst({
    where: {
      id,
      orgId: organizationId,
    },
  });

  if (!existingAgent) {
    return next(new AppError('Agent not found', 404));
  }

  // Delete agent (this will cascade delete assessments and results)
  await prisma.agent.delete({
    where: { id },
  });

  logger.info(`Agent deleted: ${existingAgent.hostname} for organization: ${organizationId}`);

  res.status(200).json({
    status: 'success',
    message: 'Agent deleted successfully',
  });
});

/**
 * Agent heartbeat to update status and last seen
 * POST /api/agents/:id/heartbeat
 */
export const agentHeartbeat = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const { status, metadata } = HeartbeatSchema.parse(req.body);
  const organizationId = req.user!.organizationId;

  // Check if agent exists and belongs to organization
  const existingAgent = await prisma.agent.findFirst({
    where: {
      id,
      orgId: organizationId,
    },
  });

  if (!existingAgent) {
    return next(new AppError('Agent not found', 404));
  }

  // Prepare update data
  const updateData: any = {
    status,
    lastSeenAt: new Date(),
  };

  if (metadata && Object.keys(metadata).length > 0) {
    const existingConfig = parseAgentConfiguration(existingAgent.configuration);
    updateData.configuration = JSON.stringify({
      ...existingConfig,
      lastHeartbeatMetadata: metadata,
      lastHeartbeatAt: new Date().toISOString(),
    });
  }

  // Update agent status and last seen
  const agent = await prisma.agent.update({
    where: { id },
    data: updateData,
  });

  res.status(200).json({
    status: 'success',
    message: 'Heartbeat received',
    data: { agent },
  });
});

/**
 * Get agent statistics for the organization
 * GET /api/agents/stats
 */
export const getAgentStats = catchAsync(async (req: Request, res: Response) => {
  const organizationId = req.user!.organizationId;

  const stats = await prisma.agent.groupBy({
    by: ['status'],
    where: { orgId: organizationId },
    _count: true,
  });

  const totalAgents = await prisma.agent.count({
    where: { orgId: organizationId },
  });

  const recentlyActive = await prisma.agent.count({
    where: {
      orgId: organizationId,
      lastSeenAt: {
        gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
      },
    },
  });

  const statusCounts = stats.reduce((acc, stat) => {
    acc[stat.status] = stat._count;
    return acc;
  }, {} as Record<string, number>);

  res.status(200).json({
    status: 'success',
    data: {
      totalAgents,
      recentlyActive,
      statusCounts,
    },
  });
});

/**
 * Download organization-specific agent executable
 * GET /api/agents/download
 */
export const downloadAgent = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const organizationId = req.user!.organizationId;

  // Generate agent configuration for the organization
  const organization = await prisma.organization.findUnique({
    where: { id: organizationId },
    select: { id: true, name: true, settings: true }
  });

  if (!organization) {
    return next(new AppError('Organization not found', 404));
  }

  // Check for organization-specific pre-built agent
  const agentFileName = `decian-agent-${organizationId}.exe`;
  const agentsDir = path.join(process.cwd(), '..', 'agents', 'dist');
  const agentPath = path.join(agentsDir, agentFileName);

  logger.info(`Agent download requested for organization: ${organizationId}`);
  logger.info(`Process working directory: ${process.cwd()}`);
  logger.info(`Agents directory: ${agentsDir}`);
  logger.info(`Looking for pre-built agent at: ${agentPath}`);
  logger.info(`File exists check: ${fs.existsSync(agentPath)}`);

  if (fs.existsSync(agentPath)) {
    // Serve the pre-built organization-specific agent
    logger.info(`Serving pre-built agent for organization: ${organizationId}`);

    res.setHeader('Content-Disposition', `attachment; filename="${agentFileName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', fs.statSync(agentPath).size.toString());

    const fileStream = fs.createReadStream(agentPath);
    fileStream.pipe(res);

    fileStream.on('error', (error) => {
      logger.error('Error streaming agent file', { error: error.message });
      return next(new AppError('Failed to download agent', 500));
    });

    fileStream.on('end', () => {
      logger.info(`Agent downloaded successfully for organization: ${organizationId}`);
    });
  } else {
    // No pre-built agent exists, build one on-demand
    logger.info(`No pre-built agent found, building on-demand for organization: ${organizationId}`);

    try {
      const built = await buildAgentForOrganization(organization);

      if (built && fs.existsSync(agentPath)) {
        // Agent was built successfully, serve it
        logger.info(`Agent built successfully, serving for organization: ${organizationId}`);

        res.setHeader('Content-Disposition', `attachment; filename="${agentFileName}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', fs.statSync(agentPath).size.toString());

        const fileStream = fs.createReadStream(agentPath);
        fileStream.pipe(res);

        fileStream.on('error', (error) => {
          logger.error('Error streaming built agent file', { error: error.message });
          return next(new AppError('Failed to download agent', 500));
        });

        fileStream.on('end', () => {
          logger.info(`Built agent downloaded successfully for organization: ${organizationId}`);
        });
      } else {
        // Build failed, fall back to providing configuration and instructions
        logger.warn(`Agent build failed for organization: ${organizationId}, providing fallback instructions`);
        return provideFallbackInstructions(organization, res);
      }
    } catch (error) {
      logger.error('Error building agent', {
        organizationId,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return provideFallbackInstructions(organization, res);
    }
  }
});

/**
 * Build agent executable for a specific organization
 */
async function buildAgentForOrganization(organization: { id: string; name: string; settings: any }): Promise<boolean> {
  const organizationId = organization.id;
  const dashboardUrl = process.env.DASHBOARD_URL || 'https://localhost:3001';

  try {
    logger.info(`Building agent for organization: ${organizationId}`);

    // Ensure dist directory exists
    const agentsDir = path.join(process.cwd(), '..', 'agents');
    const distDir = path.join(agentsDir, 'dist');
    const scriptsDir = path.join(agentsDir, 'scripts');

    if (!fs.existsSync(distDir)) {
      fs.mkdirSync(distDir, { recursive: true });
    }

    // Use PowerShell script on Windows, bash script on others
    const isWindows = process.platform === 'win32';
    const buildScript = isWindows ? 'build-agent.ps1' : 'build-agent.sh';
    const buildScriptPath = path.join(scriptsDir, buildScript);

    if (!fs.existsSync(buildScriptPath)) {
      logger.error(`Build script not found: ${buildScriptPath}`);
      return false;
    }

    // Build command
    let buildCommand: string;
    if (isWindows) {
      buildCommand = `powershell.exe -ExecutionPolicy Bypass -File "${buildScriptPath}" -OrgId "${organizationId}" -DashboardUrl "${dashboardUrl}" -OutputDir "dist"`;
    } else {
      buildCommand = `bash "${buildScriptPath}" --org-id "${organizationId}" --dashboard-url "${dashboardUrl}" --output-dir "dist"`;
    }

    logger.info(`Executing build command: ${buildCommand}`);

    // Change to agents directory and execute build
    const originalCwd = process.cwd();
    process.chdir(agentsDir);

    try {
      // Execute build with timeout (5 minutes)
      execSync(buildCommand, {
        timeout: 5 * 60 * 1000,
        stdio: 'pipe',
        encoding: 'utf8'
      });

      logger.info(`Agent built successfully for organization: ${organizationId}`);
      return true;

    } catch (error: any) {
      logger.error(`Build command failed for organization ${organizationId}:`, {
        command: buildCommand,
        error: error.message,
        stdout: error.stdout,
        stderr: error.stderr
      });
      return false;
    } finally {
      process.chdir(originalCwd);
    }

  } catch (error) {
    logger.error(`Error building agent for organization ${organizationId}:`, {
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    return false;
  }
}

/**
 * Provide fallback instructions when agent build fails
 */
function provideFallbackInstructions(organization: { id: string; name: string; settings: any }, res: Response) {
  const agentConfig = {
    dashboardUrl: process.env.DASHBOARD_URL || 'https://localhost:3001',
    organizationId: organization.id,
    organizationName: organization.name,
    modules: [
      'MISCONFIGURATION_DISCOVERY',
      'WEAK_PASSWORD_DETECTION',
      'DATA_EXPOSURE_CHECK',
      'PHISHING_EXPOSURE_INDICATORS',
      'PATCH_UPDATE_STATUS',
      'ELEVATED_PERMISSIONS_REPORT',
      'EXCESSIVE_SHARING_RISKS',
      'PASSWORD_POLICY_WEAKNESS',
      'OPEN_SERVICE_PORT_ID',
      'USER_BEHAVIOR_RISK_SIGNALS'
    ],
    settings: organization.settings || {}
  };

  const configYaml = `# Decian Security Agent Configuration
# Organization: ${organization.name}

dashboard:
  url: "${agentConfig.dashboardUrl}"
  organization_id: "${agentConfig.organizationId}"

agent:
  version: "2.0.0"
  timeout: 300
  log_level: "INFO"

modules:
${agentConfig.modules.map(module => `  - "${module}"`).join('\n')}

security:
  tls_version: "1.3"
  certificate_pinning: true
  encryption: true
  hmac_validation: true

settings:
  retry_attempts: 3
  retry_delay: "5s"
  heartbeat_interval: "60s"
`;

  const instructions = `# Decian Security Agent Setup Instructions

## Automatic Setup (Recommended)
The agent executable should contain embedded configuration for automatic setup.

1. **Download the Agent**:
   - Download: decian-agent-${organization.id}.exe

2. **Run Setup**:
   \`\`\`powershell
   .\\decian-agent-${organization.id}.exe setup
   \`\`\`

3. **Run Assessment**:
   \`\`\`powershell
   .\\decian-agent-${organization.id}.exe run
   \`\`\`

## Manual Setup (If automatic fails)
If the automatic setup fails, you can build manually:

1. **Download Go**: https://golang.org/download/
2. **Download Source**: Clone the agent repository
3. **Save Config**: Save the configuration below as \`.decian-agent.yaml\`
4. **Build**: \`go build -o decian-agent.exe\`
5. **Register**: \`./decian-agent.exe register\`
6. **Run**: \`./decian-agent.exe run\`

## Available Security Modules
${agentConfig.modules.map((module, index) => `${index + 1}. ${module.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase())}`).join('\n')}
`;

  res.status(200).json({
    status: 'success',
    message: 'Agent build failed. Please use the manual build instructions below.',
    data: {
      config: configYaml,
      instructions: instructions,
      downloadUrl: null,
      buildRequired: true,
      organizationId: organization.id,
      agentFileName: `decian-agent-${organization.id}.exe`
    }
  });

  logger.info(`Agent configuration provided for organization: ${organization.id}`);
}