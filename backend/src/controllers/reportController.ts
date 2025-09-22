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
      templateVersion: '1.0.0',
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
 * Generate HTML report content
 */
function generateHTMLReport(assessment: any, options: any): string {
  const { includeDetails, includeExecutiveSummary } = options;

  // Calculate risk statistics
  const results = assessment.results;
  const riskCounts = results.reduce((acc: any, result: any) => {
    acc[result.riskLevel] = (acc[result.riskLevel] || 0) + 1;
    return acc;
  }, {});

  const criticalCount = riskCounts.CRITICAL || 0;
  const highCount = riskCounts.HIGH || 0;
  const mediumCount = riskCounts.MEDIUM || 0;
  const lowCount = riskCounts.LOW || 0;

  const overallRisk = assessment.overallRiskScore || 0;
  const riskColor = overallRisk >= 70 ? '#dc2626' : overallRisk >= 40 ? '#ea580c' : '#16a34a';

  let html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${assessment.organization.name} - Security Assessment Report</title>
    <style>
        body {
            font-family: Inter, -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: #374151;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9fafb;
        }
        .header {
            background: linear-gradient(135deg, #2563eb 0%, #3b82f6 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5rem;
            font-weight: 700;
        }
        .header p {
            margin: 0;
            font-size: 1.1rem;
            opacity: 0.9;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .risk-score {
            font-size: 3rem;
            font-weight: 800;
            color: ${riskColor};
            text-align: center;
            margin: 20px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #f8fafc;
        }
        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #d97706; }
        .low { color: #16a34a; }
        .results-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .results-table th,
        .results-table td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }
        .results-table th {
            background-color: #f9fafb;
            font-weight: 600;
        }
        .risk-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        .risk-critical { background: #fef2f2; color: #991b1b; }
        .risk-high { background: #fff7ed; color: #c2410c; }
        .risk-medium { background: #fefce8; color: #a16207; }
        .risk-low { background: #f0fdf4; color: #166534; }
        .metadata {
            background: #f8fafc;
            padding: 16px;
            border-radius: 6px;
            margin: 20px 0;
        }
        .metadata strong {
            color: #374151;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>${assessment.organization.name}</p>
    </div>`;

  if (includeExecutiveSummary) {
    html += `
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="risk-score">${overallRisk.toFixed(1)}</div>
        <p style="text-align: center; font-size: 1.1rem; margin-bottom: 30px;">
            Overall Risk Score
        </p>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number critical">${criticalCount}</div>
                <div>Critical Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high">${highCount}</div>
                <div>High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium">${mediumCount}</div>
                <div>Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low">${lowCount}</div>
                <div>Low Risk</div>
            </div>
        </div>
    </div>`;
  }

  html += `
    <div class="card">
        <h2>Assessment Details</h2>
        <div class="metadata">
            <strong>Agent:</strong> ${assessment.agent.hostname}<br>
            <strong>Agent Version:</strong> ${assessment.agent.version}<br>
            <strong>Assessment Start:</strong> ${new Date(assessment.startTime).toLocaleString()}<br>
            <strong>Assessment End:</strong> ${assessment.endTime ? new Date(assessment.endTime).toLocaleString() : 'N/A'}<br>
            <strong>Total Checks:</strong> ${results.length}<br>
            <strong>Report Generated:</strong> ${new Date().toLocaleString()}
        </div>
    </div>`;

  if (includeDetails && results.length > 0) {
    html += `
    <div class="card">
        <h2>Detailed Results</h2>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Check Type</th>
                    <th>Risk Level</th>
                    <th>Risk Score</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>`;

    results.forEach((result: any) => {
      const riskClass = `risk-${result.riskLevel.toLowerCase()}`;
      const checkType = result.checkType.replace(/_/g, ' ').toLowerCase()
        .replace(/\b\w/g, (l: string) => l.toUpperCase());

      html += `
                <tr>
                    <td>${checkType}</td>
                    <td><span class="risk-badge ${riskClass}">${result.riskLevel}</span></td>
                    <td>${result.riskScore.toFixed(1)}</td>
                    <td>${JSON.stringify(result.resultData, null, 2).substring(0, 200)}...</td>
                </tr>`;
    });

    html += `
            </tbody>
        </table>
    </div>`;
  }

  html += `
    <div class="footer">
        <p>Generated by Decian Cybersecurity Assessment Platform</p>
        <p>Report ID: ${assessment.id}</p>
    </div>
</body>
</html>`;

  return html;
}