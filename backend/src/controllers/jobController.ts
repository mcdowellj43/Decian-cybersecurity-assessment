import { Request, Response, NextFunction } from 'express';
import { AgentStatus, AssessmentStatus, JobStatus, Prisma } from '@prisma/client';
import { prisma } from '@/utils/database';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { isJobsApiEnabled } from '@/config/featureFlags';
import { z } from 'zod';

const MAX_WAIT_SECONDS = 30;

const ResultSchema = z.object({
  status: z.nativeEnum(JobStatus).refine(
    (status) => status === JobStatus.SUCCEEDED || status === JobStatus.FAILED,
    'Result status must be SUCCEEDED or FAILED'
  ),
  summary: z.record(z.any()).optional().default({}),
  artifactUrl: z.string().url().optional(),
});

export const nextJobs = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled', 404));
  }

  if (!req.agent) {
    return next(new AppError('Agent context missing', 401));
  }

  const waitSeconds = Math.max(
    0,
    Math.min(Number(req.query.wait ?? 0), MAX_WAIT_SECONDS)
  );
  const deadline = Date.now() + waitSeconds * 1000;
  let job = await findQueuedJob(req.agent.agentId, req.agent.orgId);

  while (!job && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    job = await findQueuedJob(req.agent.agentId, req.agent.orgId);
  }

  await prisma.agent.update({
    where: { id: req.agent.agentId },
    data: { lastSeenAt: new Date(), status: AgentStatus.ONLINE },
  });

  if (!job) {
    return res.status(200).json({ status: 'success', data: [] });
  }

  return res.status(200).json({
    status: 'success',
    data: [
      {
        jobId: job.id,
        type: job.type,
        payload: job.payload,
      },
    ],
  });
});

export const ackJob = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  await transitionJob(req, res, next, JobStatus.QUEUED, JobStatus.DISPATCHED, {
    attempts: { increment: 1 },
  });
});

export const startJob = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  await transitionJob(req, res, next, JobStatus.DISPATCHED, JobStatus.RUNNING, {
    result: {
      upsert: {
        update: { startedAt: new Date(), status: JobStatus.RUNNING },
        create: {
          status: JobStatus.RUNNING,
          summary: {},
          startedAt: new Date(),
        },
      },
    },
  });
});

export const submitJobResults = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled', 404));
  }

  if (!req.agent) {
    return next(new AppError('Agent context missing', 401));
  }

  const { jobId } = req.params as { jobId: string };
  const parsed = ResultSchema.parse(req.body);

  const job = await prisma.job.findUnique({
    where: { id: jobId },
    include: { result: true },
  });

  if (!job || job.agentId !== req.agent.agentId || job.orgId !== req.agent.orgId) {
    throw new AppError('Job not found for agent', 404);
  }

  if (job.status === JobStatus.SUCCEEDED || job.status === JobStatus.FAILED || job.status === JobStatus.EXPIRED) {
    return res.status(204).end();
  }

  await prisma.$transaction([
    prisma.job.update({
      where: { id: jobId },
      data: {
        status: parsed.status,
        updatedAt: new Date(),
      },
    }),
    prisma.jobResult.upsert({
      where: { jobId },
      update: {
        status: parsed.status,
        summary: parsed.summary,
        artifactUrl: parsed.artifactUrl,
        finishedAt: new Date(),
      },
      create: {
        jobId,
        status: parsed.status,
        summary: parsed.summary,
        artifactUrl: parsed.artifactUrl,
        startedAt: job.result?.startedAt ?? new Date(),
        finishedAt: new Date(),
      },
    }),
  ]);

  await maybeUpdateAssessment(job, parsed.status);

  return res.status(204).end();
});

export const signArtifactUpload = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled', 404));
  }

  if (!req.agent) {
    return next(new AppError('Agent context missing', 401));
  }

  const { jobId } = req.params as { jobId: string };
  const job = await prisma.job.findUnique({ where: { id: jobId } });
  if (!job || job.agentId !== req.agent.agentId) {
    throw new AppError('Job not found for agent', 404);
  }

  const baseUrl = process.env.ARTIFACT_PUT_BASE_URL || 'https://artifacts.example.com/uploads';
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
  const url = `${baseUrl}/${jobId}/${Date.now()}`;

  return res.status(200).json({
    status: 'success',
    data: {
      url,
      headers: {
        'x-mock-signed': 'true',
      },
      expiresAt: expiresAt.toISOString(),
    },
  });
});

const findQueuedJob = (agentId: string, orgId: string) => {
  return prisma.job.findFirst({
    where: {
      agentId,
      orgId,
      status: JobStatus.QUEUED,
      OR: [
        { notBefore: null },
        { notBefore: { lte: new Date() } },
      ],
    },
    orderBy: { createdAt: 'asc' },
  });
};

const transitionJob = async (
  req: Request,
  res: Response,
  next: NextFunction,
  expectedStatus: JobStatus,
  targetStatus: JobStatus,
  extraData: Prisma.JobUpdateInput = {}
) => {
  if (!isJobsApiEnabled()) {
    return next(new AppError('Jobs API is not enabled', 404));
  }

  if (!req.agent) {
    return next(new AppError('Agent context missing', 401));
  }

  const { jobId } = req.params as { jobId: string };
  const job = await prisma.job.findUnique({ where: { id: jobId } });
  if (!job || job.agentId !== req.agent.agentId || job.orgId !== req.agent.orgId) {
    throw new AppError('Job not found for agent', 404);
  }

  if (job.status === targetStatus) {
    return res.status(204).end();
  }

  if (job.status !== expectedStatus && !(expectedStatus === JobStatus.DISPATCHED && job.status === JobStatus.RUNNING)) {
    return res.status(409).json({ status: 'fail', message: `Job not in expected state (${expectedStatus})` });
  }

  await prisma.job.update({
    where: { id: jobId },
    data: {
      status: targetStatus,
      updatedAt: new Date(),
      ...extraData,
    },
  });

  return res.status(204).end();
};

const maybeUpdateAssessment = async (job: { payload: unknown }, status: JobStatus) => {
  if (typeof job.payload !== 'object' || job.payload === null) {
    return;
  }

  const payload = job.payload as Record<string, unknown>;
  if (typeof payload.assessmentId !== 'string') {
    return;
  }

  const assessmentId = payload.assessmentId;
  const nextStatus = status === JobStatus.SUCCEEDED ? AssessmentStatus.COMPLETED : AssessmentStatus.FAILED;

  await prisma.assessment.updateMany({
    where: { id: assessmentId },
    data: {
      status: nextStatus,
      endTime: new Date(),
    },
  });
};
