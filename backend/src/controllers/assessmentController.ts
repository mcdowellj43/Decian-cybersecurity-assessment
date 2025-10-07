import { Request, Response, NextFunction } from 'express';
import { AssessmentStatus, CheckType, RiskLevel, JobStatus } from '@prisma/client';
import { prisma } from '@/utils/database';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { z } from 'zod';
import { isJobsApiEnabled } from '@/config/featureFlags';

// Validation schemas
const CreateAssessmentSchema = z.object({
  agentId: z.string().min(1, 'Agent ID is required'),
  modules: z.array(z.nativeEnum(CheckType)).min(1, 'At least one module must be selected'),
  metadata: z.record(z.any()).optional().default({}),
});

const SubmitResultsSchema = z.object({
  results: z.array(z.object({
    checkType: z.nativeEnum(CheckType),
    resultData: z.record(z.any()),
    riskScore: z.number().min(0).max(100),
    riskLevel: z.nativeEnum(RiskLevel),
  })).min(1, 'At least one result must be provided'),
  overallRiskScore: z.number().min(0).max(100).optional(),
});

const EnqueueJobsSchema = z.object({
  agentIds: z.array(z.string().min(1)).min(1),
  modules: z.array(z.string().min(1)).min(1),
  options: z.record(z.any()).optional(),
});

/**
 * Create a new assessment
 * POST /api/assessments
 */
export const createAssessment = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { agentId, modules, metadata } = CreateAssessmentSchema.parse(req.body);
  const organizationId = req.user!.organizationId;

  // Verify agent exists and belongs to organization
  const agent = await prisma.agent.findFirst({
    where: {
      id: agentId,
      orgId: organizationId,
    },
  });

  if (!agent) {
    return next(new AppError('Agent not found or does not belong to your organization', 404));
  }

  // Check if there's already a running assessment for this agent
  const runningAssessment = await prisma.assessment.findFirst({
    where: {
      agentId,
      status: {
        in: [AssessmentStatus.PENDING, AssessmentStatus.RUNNING],
      },
    },
  });

  if (runningAssessment) {
    return next(new AppError('Agent already has a running assessment', 409));
  }

  // Create assessment
  const assessment = await prisma.assessment.create({
    data: {
      organizationId,
      agentId,
      status: AssessmentStatus.PENDING,
      startTime: new Date(),
      metadata: JSON.stringify({
        ...metadata,
        selectedModules: modules,
        requestedBy: req.user!.id,
      }),
    },
    include: {
      agent: {
        select: {
          id: true,
          hostname: true,
          status: true,
        },
      },
    },
  });

  logger.info(`Assessment created: ${assessment.id} for agent: ${agent.hostname}`);

  res.status(201).json({
    status: 'success',
    message: 'Assessment created successfully',
    data: { assessment },
  });
});

/**
 * Get all assessments for the organization
 * GET /api/assessments
 */
export const getAssessments = catchAsync(async (req: Request, res: Response) => {
  const organizationId = req.user!.organizationId;
  const {
    status,
    agentId,
    limit = 50,
    offset = 0,
    sortBy = 'createdAt',
    sortOrder = 'desc',
  } = req.query;

  const where: any = { organizationId };

  if (status && Object.values(AssessmentStatus).includes(status as AssessmentStatus)) {
    where.status = status;
  }

  if (agentId) {
    where.agentId = agentId;
  }

  const orderBy: any = {};
  orderBy[sortBy as string] = sortOrder;

  const assessments = await prisma.assessment.findMany({
    where,
    orderBy,
    take: Number(limit),
    skip: Number(offset),
    include: {
      agent: {
        select: {
          id: true,
          hostname: true,
          status: true,
        },
      },
      results: {
        select: {
          checkType: true,
          riskLevel: true,
          riskScore: true,
        },
      },
      _count: {
        select: {
          results: true,
        },
      },
    },
  });

  const total = await prisma.assessment.count({ where });

  res.status(200).json({
    status: 'success',
    data: {
      assessments,
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
 * Get specific assessment details
 * GET /api/assessments/:id
 */
export const getAssessmentById = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  const assessment = await prisma.assessment.findFirst({
    where: {
      id,
      organizationId,
    },
    include: {
      agent: {
        select: {
          id: true,
          hostname: true,
          status: true,
          version: true,
        },
      },
      results: {
        orderBy: { createdAt: 'asc' },
      },
      reports: {
        select: {
          id: true,
          title: true,
          createdAt: true,
        },
      },
    },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { assessment },
  });
});

/**
 * Submit assessment results from agent
 * PUT /api/assessments/:id/results
 */
export const submitAssessmentResults = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const { results, overallRiskScore } = SubmitResultsSchema.parse(req.body);
  const organizationId = req.user!.organizationId;

  // Find assessment and verify it belongs to organization
  const assessment = await prisma.assessment.findFirst({
    where: {
      id,
      organizationId,
    },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  // Check if assessment is in a state that can receive results
  if (assessment.status !== AssessmentStatus.PENDING && assessment.status !== AssessmentStatus.RUNNING) {
    return next(new AppError('Assessment is not in a state to receive results', 400));
  }

  // Calculate overall risk score if not provided
  const calculatedRiskScore = overallRiskScore ||
    Math.round(results.reduce((sum, result) => sum + result.riskScore, 0) / results.length);

  // Use transaction to update assessment and create results
  const updatedAssessment = await prisma.$transaction(async (tx) => {
    // Delete existing results if any (for resubmission cases)
    await tx.assessmentResult.deleteMany({
      where: { assessmentId: id },
    });

    // Create new results
    await tx.assessmentResult.createMany({
      data: results.map(result => ({
        assessmentId: id as string,
        checkType: result.checkType,
        resultData: JSON.stringify(result.resultData),
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
      })),
    });

    // Update assessment status and risk score
    return tx.assessment.update({
      where: { id },
      data: {
        status: AssessmentStatus.COMPLETED,
        endTime: new Date(),
        overallRiskScore: calculatedRiskScore,
      },
      include: {
        agent: {
          select: {
            hostname: true,
          },
        },
        results: true,
      },
    });
  });

  logger.info(`Assessment results submitted: ${id} for agent: ${updatedAssessment.agent.hostname}`);

  res.status(200).json({
    status: 'success',
    message: 'Assessment results submitted successfully',
    data: { assessment: updatedAssessment },
  });
});

/**
 * Stop a running assessment
 * POST /api/assessments/:id/stop
 */
export const stopAssessment = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  const assessment = await prisma.assessment.findFirst({
    where: {
      id,
      organizationId,
    },
    include: {
      agent: {
        select: {
          hostname: true,
        },
      },
    },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  // Check if assessment can be stopped
  if (assessment.status !== AssessmentStatus.PENDING && assessment.status !== AssessmentStatus.RUNNING) {
    return next(new AppError('Assessment cannot be stopped in current state', 400));
  }

  // Update assessment status
  const updatedAssessment = await prisma.assessment.update({
    where: { id },
    data: {
      status: AssessmentStatus.FAILED,
      endTime: new Date(),
      metadata: JSON.stringify({
        ...safeJsonParse(assessment.metadata ?? '{}'),
        stoppedBy: req.user!.id,
        stoppedAt: new Date().toISOString(),
        reason: 'Manually stopped by user',
      }),
    },
  });

  logger.info(`Assessment stopped: ${id} for agent: ${assessment.agent.hostname}`);

  res.status(200).json({
    status: 'success',
    message: 'Assessment stopped successfully',
    data: { assessment: updatedAssessment },
  });
});

/**
 * Delete an assessment and its results
 * DELETE /api/assessments/:id
 */
export const deleteAssessment = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  const assessment = await prisma.assessment.findFirst({
    where: {
      id,
      organizationId,
    },
    include: {
      agent: {
        select: {
          hostname: true,
        },
      },
    },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  // Delete assessment (this will cascade delete results and reports)
  await prisma.assessment.delete({
    where: { id },
  });

  logger.info(`Assessment deleted: ${id} for agent: ${assessment.agent.hostname}`);

  res.status(200).json({
    status: 'success',
    message: 'Assessment deleted successfully',
  });
});

/**
 * Get assessment statistics for the organization
 * GET /api/assessments/stats?organizationId=<optional>
 */
export const getAssessmentStats = catchAsync(async (req: Request, res: Response) => {
  const { organizationId: requestedOrgId } = req.query;
  const userOrgId = req.user!.organizationId;
  const userRole = req.user!.role;

  // Allow organization ID parameter for admins, otherwise use user's organization
  let organizationId = userOrgId;
  if (requestedOrgId && typeof requestedOrgId === 'string') {
    // Only admins can query other organizations
    if (userRole === 'ADMIN') {
      organizationId = requestedOrgId;
    } else if (requestedOrgId !== userOrgId) {
      return res.status(403).json({
        status: 'error',
        message: 'Insufficient permissions to access other organization data',
      });
    }
  }

  // Get status distribution
  const statusStats = await prisma.assessment.groupBy({
    by: ['status'],
    where: { organizationId },
    _count: true,
  });

  // Get recent assessments count (last 30 days)
  const recentAssessments = await prisma.assessment.count({
    where: {
      organizationId,
      createdAt: {
        gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      },
    },
  });

  // Get average risk score
  const riskScoreAvg = await prisma.assessment.aggregate({
    where: {
      organizationId,
      overallRiskScore: { not: null },
    },
    _avg: {
      overallRiskScore: true,
    },
  });

  // Get total assessments
  const totalAssessments = await prisma.assessment.count({
    where: { organizationId },
  });

  const statusCounts = statusStats.reduce((acc, stat) => {
    acc[stat.status] = stat._count;
    return acc;
  }, {} as Record<string, number>);

  res.status(200).json({
    status: 'success',
    data: {
      totalAssessments,
      recentAssessments,
      averageRiskScore: riskScoreAvg._avg.overallRiskScore || 0,
      statusCounts,
    },
  });
});
export const enqueueAssessmentJobs = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled for this environment', 409));
  }

  const { assessmentId } = req.params;
  const organizationId = req.user!.organizationId;
  const { agentIds, modules, options } = EnqueueJobsSchema.parse(req.body);

  const assessment = await prisma.assessment.findFirst({
    where: { id: assessmentId, organizationId },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  const agents = await prisma.agent.findMany({
    where: {
      id: { in: agentIds },
      orgId: organizationId,
    },
  });

  if (agents.length !== agentIds.length) {
    return next(new AppError('One or more agents are invalid for this organization', 400));
  }

  const payload = {
    assessmentId,
    modules,
    options: options ?? {},
    version: '1',
  };

  const jobs = await prisma.$transaction(
    agents.map((agent) =>
      prisma.job.create({
        data: {
          orgId: organizationId,
          agentId: agent.id,
          type: 'ASSESSMENT',
          payload,
          status: JobStatus.QUEUED,
          dedupeKey: `${assessmentId}:${agent.id}`,
        },
      })
    )
  );

  const currentMetadata = safeJsonParse(assessment.metadata ?? '{}');
  const mergedMetadata = {
    ...currentMetadata,
    modules,
    agentIds,
    options: options ?? {},
  };

  await prisma.assessment.update({
    where: { id: assessmentId },
    data: {
      status: AssessmentStatus.PENDING,
      metadata: JSON.stringify(mergedMetadata),
    },
  });

  return res.status(202).json({
    status: 'success',
    data: {
      jobs,
    },
  });
});

const safeJsonParse = (value: string): Record<string, unknown> => {
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
};
