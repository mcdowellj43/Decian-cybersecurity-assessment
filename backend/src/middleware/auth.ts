import { Request, Response, NextFunction } from 'express';
import { UserRole } from '@prisma/client';
import { verifyAccessToken, extractTokenFromHeader } from '@/utils/jwt';
import { prisma } from '@/utils/database';
import { AppError } from './errorHandler';
import { logger } from '@/utils/logger';
import { AuthUser } from '@/types/auth';

// Extend Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

/**
 * Middleware to authenticate JWT tokens
 */
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // Extract token from Authorization header
    const token = extractTokenFromHeader(req.headers.authorization);

    if (!token) {
      return next(new AppError('Access token is required', 401));
    }

    // Verify the token
    const payload = verifyAccessToken(token);

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      include: {
        organization: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    if (!user) {
      return next(new AppError('User not found', 401));
    }

    // Check if user's organization matches token
    if (user.organizationId !== payload.organizationId) {
      return next(new AppError('Invalid token organization', 401));
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      organizationId: user.organizationId,
      organizationName: user.organization.name,
    };

    // Update last login time
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    next();
  } catch (error) {
    logger.error('Authentication error:', error);
    next(new AppError('Invalid or expired token', 401));
  }
};

/**
 * Middleware to authorize specific roles
 */
export const authorize = (...roles: UserRole[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('Insufficient permissions for this action', 403)
      );
    }

    next();
  };
};

/**
 * Middleware for admin-only routes
 */
export const requireAdmin = authorize(UserRole.ADMIN);

/**
 * Middleware for admin and user roles
 */
export const requireUser = authorize(UserRole.ADMIN, UserRole.USER);

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
export const optionalAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = extractTokenFromHeader(req.headers.authorization);

    if (token) {
      const payload = verifyAccessToken(token);
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        include: {
          organization: {
            select: {
              id: true,
              name: true,
            },
          },
        },
      });

      if (user && user.organizationId === payload.organizationId) {
        req.user = {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          organizationId: user.organizationId,
          organizationName: user.organization.name,
        };
      }
    }

    next();
  } catch (error) {
    // For optional auth, we don't fail on token errors
    logger.debug('Optional auth failed:', error);
    next();
  }
};