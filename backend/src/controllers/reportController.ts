import { Request, Response, NextFunction } from 'express';
import { prisma } from '@/utils/database';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { z } from 'zod';

// Validation schemas
const GenerateReportSchema = z.object({
  assessmentId: z.string().min(1, 'Assessment ID is required'),
  title: z.string().optional(),
  includeDetails: z.boolean().optional().default(true),
  includeExecutiveSummary: z.boolean().optional().default(true),
});

/**
 * Generate HTML report from assessment
 * POST /api/reports/generate
 */
export const generateReport = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { assessmentId, title, includeDetails, includeExecutiveSummary } = GenerateReportSchema.parse(req.body);
  const organizationId = req.user!.organizationId;

  // Find assessment with all related data
  const assessment = await prisma.assessment.findFirst({
    where: {
      id: assessmentId,
      organizationId,
    },
    include: {
      agent: {
        select: {
          hostname: true,
          version: true,
        },
      },
      organization: {
        select: {
          name: true,
        },
      },
      results: {
        orderBy: { riskScore: 'desc' },
      },
    },
  });

  if (!assessment) {
    return next(new AppError('Assessment not found', 404));
  }

  if (assessment.status !== 'COMPLETED') {
    return next(new AppError('Assessment must be completed to generate report', 400));
  }

  // Generate HTML content
  const htmlContent = generateHTMLReport(assessment, {
    includeDetails,
    includeExecutiveSummary,
  });

  // Create report record
  const report = await prisma.report.create({
    data: {
      assessmentId,
      title: title || `Security Assessment Report - ${assessment.agent.hostname}`,
      templateVersion: '2.0.0',
      htmlContent,
      organizationName: assessment.organization.name,
    },
  });

  logger.info(`Report generated: ${report.id} for assessment: ${assessmentId}`);

  res.status(201).json({
    status: 'success',
    message: 'Report generated successfully',
    data: { report },
  });
});

/**
 * Get available reports for organization
 * GET /api/reports
 */
export const getReports = catchAsync(async (req: Request, res: Response) => {
  const organizationId = req.user!.organizationId;
  const { limit = 50, offset = 0, assessmentId } = req.query;

  const where: any = {
    assessment: {
      organizationId,
    },
  };

  if (assessmentId) {
    where.assessmentId = assessmentId;
  }

  const reports = await prisma.report.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: Number(limit),
    skip: Number(offset),
    include: {
      assessment: {
        select: {
          id: true,
          status: true,
          overallRiskScore: true,
          startTime: true,
          endTime: true,
          agent: {
            select: {
              hostname: true,
            },
          },
        },
      },
    },
  });

  const total = await prisma.report.count({ where });

  res.status(200).json({
    status: 'success',
    data: {
      reports,
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
 * Download specific report
 * GET /api/reports/:id
 */
export const getReportById = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;
  const { format = 'html' } = req.query;

  const report = await prisma.report.findFirst({
    where: {
      id,
      assessment: {
        organizationId,
      },
    },
    include: {
      assessment: {
        select: {
          id: true,
          agent: {
            select: {
              hostname: true,
            },
          },
        },
      },
    },
  });

  if (!report) {
    return next(new AppError('Report not found', 404));
  }

  if (format === 'html') {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', `inline; filename="${report.title}.html"`);
    res.send(report.htmlContent);
  } else if (format === 'json') {
    res.status(200).json({
      status: 'success',
      data: { report },
    });
  } else {
    return next(new AppError('Unsupported format. Use html or json', 400));
  }
});

/**
 * Delete a report
 * DELETE /api/reports/:id
 */
export const deleteReport = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const organizationId = req.user!.organizationId;

  const report = await prisma.report.findFirst({
    where: {
      id,
      assessment: {
        organizationId,
      },
    },
  });

  if (!report) {
    return next(new AppError('Report not found', 404));
  }

  await prisma.report.delete({
    where: { id },
  });

  logger.info(`Report deleted: ${id}`);

  res.status(200).json({
    status: 'success',
    message: 'Report deleted successfully',
  });
});

/**
 * Generate HTML report content using professional template
 */
function generateHTMLReport(assessment: any, options: any): string {
  const { includeDetails } = options;

  // Calculate risk statistics
  const results = assessment.results;
  const riskCounts = results.reduce((acc: any, result: any) => {
    acc[result.riskLevel] = (acc[result.riskLevel] || 0) + 1;
    return acc;
  }, {});

  const criticalCount = riskCounts.CRITICAL || 0;
  const highCount = riskCounts.HIGH || 0;
  const mediumCount = riskCounts.MEDIUM || 0;

  // Group results by check type for module-based reporting
  const moduleGroups = results.reduce((acc: any, result: any) => {
    if (!acc[result.checkType]) {
      acc[result.checkType] = [];
    }
    acc[result.checkType].push(result);
    return acc;
  }, {});

  // Format module names
  const formatModuleName = (checkType: string) => {
    const moduleNames: { [key: string]: string } = {
      'SMB_SHARE_DISCOVERY': 'Shared Folder / SMB Discovery',
      'OS_FINGERPRINTING': 'Operating System Fingerprinting',
      'PORT_SERVICE_DISCOVERY': 'Port & Service Discovery',
      'WEAK_PROTOCOL_DETECTION': 'Weak Protocol Detection',
      'IOT_PRINTER_ENUMERATION': 'Printer / IoT Device Enumeration',
      'WEAK_DNS_HYGIENE': 'DNS Hygiene Check',
      'REMOTE_ACCESS_EXPOSURE': 'RDP & Remote Access Exposure',
      'TRAFFIC_VISIBILITY': 'Basic Traffic Visibility Test',
      'WEB_PORTAL_DISCOVERY': 'Default Web Page / Device Portal Check',
      'UNPATCHED_BANNER_DETECTION': 'Unpatched Service Banner Detection'
    };
    return moduleNames[checkType] || checkType.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (l: string) => l.toUpperCase());
  };

  let html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Decian - Security Assessment Report</title>
  <style>
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: #f9fafb;
      color: #1f2937;
      max-width: 1200px;
      margin: 0 auto;
      padding: 30px;
    }
    .header {
      background: linear-gradient(135deg, #1e40af, #3b82f6);
      color: white;
      padding: 40px;
      border-radius: 12px;
      text-align: center;
      margin-bottom: 40px;
    }
    .header h1 {
      margin: 0;
      font-size: 2.8rem;
      font-weight: 800;
    }
    .header p {
      margin-top: 8px;
      font-size: 1.1rem;
      opacity: 0.9;
    }
    .card {
      background: white;
      border-radius: 10px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.08);
      padding: 24px;
      margin-bottom: 24px;
    }
    .section-title {
      color: #111827;
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 10px;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin: 20px 0;
    }
    .stat-card {
      background: #f3f4f6;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }
    .stat-number {
      font-size: 2rem;
      font-weight: 700;
      color: #2563eb;
    }
    .risk-badge {
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 0.85rem;
      font-weight: 600;
    }
    .risk-critical { background: #fee2e2; color: #991b1b; }
    .risk-high { background: #fff7ed; color: #c2410c; }
    .risk-medium { background: #fefce8; color: #92400e; }
    .risk-low { background: #f0fdf4; color: #166534; }
    .insight-box {
      background: #eff6ff;
      border-left: 4px solid #2563eb;
      padding: 16px;
      border-radius: 4px;
      margin-top: 16px;
    }
    .footer {
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid #e5e7eb;
      color: #6b7280;
    }
    .module-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 16px;
    }
    .module-table th, .module-table td {
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid #e5e7eb;
    }
    .module-table th {
      background: #f9fafb;
      font-weight: 600;
    }
    .module-table tbody tr:nth-child(even) {
      background: #f9fafb;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Security Assessment Report</h1>
    <p>Generated by Decian Cybersecurity Platform</p>
  </div>

  <div class="card">
    <h2 class="section-title">Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number">${Object.keys(moduleGroups).length}</div><div>Modules Completed</div></div>
      <div class="stat-card"><div class="stat-number">1</div><div>Hosts Scanned</div></div>
      <div class="stat-card"><div class="stat-number">${criticalCount}</div><div>Critical Findings</div></div>
      <div class="stat-card"><div class="stat-number">${highCount + mediumCount}</div><div>Medium Findings</div></div>
    </div>
    <p>This automated assessment analyzed ${Object.keys(moduleGroups).length} modules covering network exposure, endpoint visibility, and service hardening. ${criticalCount > 0 ? `${criticalCount} critical risk${criticalCount > 1 ? 's were' : ' was'} detected` : 'No critical risks were detected'}, indicating ${criticalCount > 0 ? 'potential security vulnerabilities requiring immediate attention' : 'a relatively secure configuration'}.</p>
  </div>

  <div class="card">
    <h2 class="section-title">Module Overview</h2>
    <p>The following modules were executed during this assessment to evaluate different layers of the network and host environment:</p>
    <ul>`;

  Object.keys(moduleGroups).forEach(checkType => {
    html += `<li>${formatModuleName(checkType)}</li>`;
  });

  html += `
    </ul>
  </div>`;

  // Generate module-specific sections for all findings
  Object.entries(moduleGroups).forEach(([checkType, moduleResults]: [string, any]) => {
    const hasHighRiskFindings = moduleResults.some((result: any) =>
      result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH'
    );

    if (includeDetails) {
      const moduleName = formatModuleName(checkType);
      const moduleRiskCounts = moduleResults.reduce((acc: any, result: any) => {
        acc[result.riskLevel] = (acc[result.riskLevel] || 0) + 1;
        return acc;
      }, {});

      html += `
  <div class="card">
    <h2 class="section-title">${moduleName}</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-number">${moduleResults.length}</div><div>Findings</div></div>
      <div class="stat-card"><div class="stat-number">${moduleRiskCounts.HIGH || 0}</div><div>High-Risk Issues</div></div>
      <div class="stat-card"><div class="stat-number">${moduleRiskCounts.CRITICAL || 0}</div><div>Critical Issues</div></div>
      <div class="stat-card"><div class="stat-number">1</div><div>Hosts Scanned</div></div>
    </div>
    <p><strong>Summary:</strong> ${getModuleSummary(checkType, moduleResults)}</p>

    <h3>Technical Findings</h3>
    <table class="module-table">
      <thead>
        <tr>
          <th>Finding</th>
          <th>Risk Level</th>
          <th>Risk Score</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>`;

      moduleResults.forEach((result: any) => {
        const riskClass = `risk-${result.riskLevel.toLowerCase()}`;
        const details = formatResultDetails(result.resultData);

        html += `
        <tr>
          <td>${formatModuleName(result.checkType)}</td>
          <td><span class="risk-badge ${riskClass}">${result.riskLevel === 'CRITICAL' ? 'High' : result.riskLevel}</span></td>
          <td>${result.riskScore.toFixed(1)}</td>
          <td>${details}</td>
        </tr>`;
      });

      html += `
      </tbody>
    </table>

    <div class="insight-box">
      <strong>Business Insight:</strong> ${getBusinessInsight(checkType, moduleResults)}
    </div>
  </div>`;
    }
  });

  html += `
  <div class="footer">
    <p>Report Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
    <p>Decian Cybersecurity | Comprehensive Visibility. Actionable Defense.</p>
  </div>
</body>
</html>`;

  return html;
}

/**
 * Get module-specific summary text
 */
function getModuleSummary(checkType: string, results: any[]): string {
  const summaries: { [key: string]: string } = {
    'SMB_SHARE_DISCOVERY': `${results.length} SMB share${results.length > 1 ? 's were' : ' was'} discovered with potential security misconfigurations. Administrative shares with guest access pose critical risks for credential theft and ransomware propagation.`,
    'OS_FINGERPRINTING': `Operating system fingerprinting identified ${results.filter(r => r.riskLevel !== 'LOW').length} systems with incomplete visibility, indicating potential gaps in asset inventory and lifecycle tracking.`,
    'PORT_SERVICE_DISCOVERY': `Port scanning revealed ${results.length} service${results.length > 1 ? 's' : ''} with varying security configurations and potential exposure risks.`,
    'WEAK_PROTOCOL_DETECTION': `Analysis detected ${results.filter(r => r.riskLevel === 'HIGH' || r.riskLevel === 'CRITICAL').length} instance${results.filter(r => r.riskLevel === 'HIGH' || r.riskLevel === 'CRITICAL').length > 1 ? 's' : ''} of weak or deprecated protocols that could compromise data integrity.`,
    'REMOTE_ACCESS_EXPOSURE': `Remote access services assessment identified ${results.length} potential exposure point${results.length > 1 ? 's' : ''} requiring security hardening.`
  };

  return summaries[checkType] || `Assessment of ${checkType.replace(/_/g, ' ').toLowerCase()} identified ${results.length} finding${results.length > 1 ? 's' : ''} requiring attention.`;
}

/**
 * Get business insight for module
 */
function getBusinessInsight(checkType: string, _results: any[]): string {
  const insights: { [key: string]: string } = {
    'SMB_SHARE_DISCOVERY': 'Misconfigured SMB shares are one of the most common entry points for ransomware. Decian recommends deployment of <strong>Ironclad SIEM</strong> for monitoring SMB activity and a follow-up <strong>penetration test</strong> to validate exploitability.',
    'OS_FINGERPRINTING': 'Incomplete OS identification can obscure visibility into unpatched or rogue devices. Decian recommends ongoing endpoint discovery and automated patch monitoring via <strong>Ironclad SIEM</strong> integration.',
    'PORT_SERVICE_DISCOVERY': 'Exposed services increase attack surface area. Regular service auditing and network segmentation help minimize risk exposure.',
    'WEAK_PROTOCOL_DETECTION': 'Legacy protocols lack modern security controls. Migration to secure alternatives and protocol hardening reduce compromise risk.',
    'REMOTE_ACCESS_EXPOSURE': 'Remote access vectors require enhanced monitoring and access controls to prevent unauthorized entry.'
  };

  return insights[checkType] || 'Regular security assessments help maintain visibility into evolving risk landscapes and support proactive security posture improvements.';
}

/**
 * Format result details for display
 */
function formatResultDetails(resultData: string): string {
  try {
    const parsed = JSON.parse(resultData);
    if (typeof parsed === 'object') {
      // Extract key information for display
      const keys = Object.keys(parsed).slice(0, 3);
      const summary = keys.map(key => `${key}: ${String(parsed[key]).substring(0, 50)}`).join(', ');
      return summary.length > 150 ? summary.substring(0, 150) + '...' : summary;
    }
    return String(parsed).substring(0, 200);
  } catch {
    return resultData.substring(0, 200) + (resultData.length > 200 ? '...' : '');
  }
}