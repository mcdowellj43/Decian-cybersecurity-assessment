import { Request, Response, NextFunction } from 'express';
import { prisma } from '@/utils/database';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { createEnrollmentToken } from '@/utils/enrollmentToken';
import bcrypt from 'bcryptjs';

/**
 * Get all organizations (admin only)
 */
export const getOrganizations = catchAsync(async (req: Request, res: Response) => {
  const organizations = await prisma.organization.findMany({
    include: {
      _count: {
        select: {
          users: true,
          agents: true,
          assessments: true,
        },
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  res.status(200).json({
    status: 'success',
    data: { organizations },
  });
});

/**
 * Get single organization
 */
export const getOrganization = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const userOrgId = req.user!.organizationId;

  // Users can only access their own organization unless they're admin
  if (req.user!.role !== 'ADMIN' && id !== userOrgId) {
    return next(new AppError('Access denied', 403));
  }

  const organization = await prisma.organization.findUnique({
    where: { id },
    include: {
      _count: {
        select: {
          users: true,
          agents: true,
          assessments: true,
        },
      },
    },
  });

  if (!organization) {
    return next(new AppError('Organization not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: { organization },
  });
});

/**
 * Create new organization (admin only)
 */
export const createOrganization = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { name, settings = {} } = req.body;

  if (!name) {
    return next(new AppError('Organization name is required', 400));
  }

  const organization = await prisma.$transaction(async (tx) => {
    const org = await tx.organization.create({
      data: {
        name,
        settings: JSON.stringify(settings),
      },
      include: {
        _count: {
          select: {
            users: true,
            agents: true,
            assessments: true,
          },
        },
      },
    });

    // Create initial enrollment token
    const enrollmentToken = await createEnrollmentToken(tx, org.id, req.user!.id);

    return { organization: org, enrollmentToken };
  });

  logger.info(`Organization created: ${name} by user: ${req.user!.email}`);

  res.status(201).json({
    status: 'success',
    message: 'Organization created successfully',
    data: {
      organization: organization.organization,
      enrollmentToken: {
        token: organization.enrollmentToken.token,
        expiresAt: organization.enrollmentToken.expiresAt.toISOString(),
      },
    },
  });
});

/**
 * Update organization
 */
export const updateOrganization = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const { name, settings } = req.body;
  const userOrgId = req.user!.organizationId;

  // Users can only update their own organization unless they're admin
  if (req.user!.role !== 'ADMIN' && id !== userOrgId) {
    return next(new AppError('Access denied', 403));
  }

  const organization = await prisma.organization.update({
    where: { id },
    data: {
      ...(name && { name }),
      ...(settings && { settings: JSON.stringify(settings) }),
    },
  });

  logger.info(`Organization updated: ${id} by user: ${req.user!.email}`);

  res.status(200).json({
    status: 'success',
    message: 'Organization updated successfully',
    data: { organization },
  });
});

/**
 * Delete organization (admin only)
 */
export const deleteOrganization = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;

  // Prevent deletion of user's own organization
  if (id === req.user!.organizationId) {
    return next(new AppError('Cannot delete your own organization', 400));
  }

  await prisma.organization.delete({
    where: { id },
  });

  logger.info(`Organization deleted: ${id} by user: ${req.user!.email}`);

  res.status(200).json({
    status: 'success',
    message: 'Organization deleted successfully',
  });
});

/**
 * Get current enrollment token for organization
 */
export const getEnrollmentToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const userOrgId = req.user!.organizationId;

  // Users can only access their own organization's token unless they're admin
  if (req.user!.role !== 'ADMIN' && id !== userOrgId) {
    return next(new AppError('Access denied', 403));
  }

  // Get the most recent unused enrollment token
  const enrollmentToken = await prisma.enrollmentToken.findFirst({
    where: {
      orgId: id,
      usedAt: null,
      expiresAt: {
        gt: new Date(),
      },
    },
    orderBy: {
      createdAt: 'desc',
    },
  });

  if (!enrollmentToken) {
    return next(new AppError('No valid enrollment token found', 404));
  }

  // Don't return the actual token hash, just metadata
  res.status(200).json({
    status: 'success',
    data: {
      enrollmentToken: {
        id: enrollmentToken.id,
        expiresAt: enrollmentToken.expiresAt.toISOString(),
        createdAt: enrollmentToken.createdAt.toISOString(),
        // Note: We don't return the actual token for security
      },
    },
  });
});

/**
 * Generate new enrollment token for organization
 */
export const regenerateEnrollmentToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const userOrgId = req.user!.organizationId;

  // Users can only regenerate their own organization's token unless they're admin
  if (req.user!.role !== 'ADMIN' && id !== userOrgId) {
    return next(new AppError('Access denied', 403));
  }

  // Verify organization exists
  const organization = await prisma.organization.findUnique({
    where: { id },
  });

  if (!organization) {
    return next(new AppError('Organization not found', 404));
  }

  const enrollmentToken = await prisma.$transaction(async (tx) => {
    return await createEnrollmentToken(tx, id, req.user!.id);
  });

  logger.info(`Enrollment token regenerated for org: ${id} by user: ${req.user!.email}`);

  res.status(200).json({
    status: 'success',
    message: 'Enrollment token regenerated successfully',
    data: {
      enrollmentToken: {
        token: enrollmentToken.token,
        expiresAt: enrollmentToken.expiresAt.toISOString(),
      },
    },
  });
});

/**
 * Get enrollment tokens history for organization
 */
export const getEnrollmentTokenHistory = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { id } = req.params;
  const userOrgId = req.user!.organizationId;

  // Users can only access their own organization's tokens unless they're admin
  if (req.user!.role !== 'ADMIN' && id !== userOrgId) {
    return next(new AppError('Access denied', 403));
  }

  const tokens = await prisma.enrollmentToken.findMany({
    where: {
      orgId: id,
    },
    select: {
      id: true,
      expiresAt: true,
      usedAt: true,
      createdAt: true,
      createdBy: true,
    },
    orderBy: {
      createdAt: 'desc',
    },
    take: 10, // Limit to last 10 tokens
  });

  res.status(200).json({
    status: 'success',
    data: { tokens },
  });
});