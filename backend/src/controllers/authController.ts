import { Request, Response, NextFunction } from 'express';
import { UserRole } from '@prisma/client';
import { prisma } from '@/utils/database';
import { generateTokens, verifyRefreshToken } from '@/utils/jwt';
import { hashPassword, comparePassword, validatePasswordStrength } from '@/utils/password';
import { AppError, catchAsync } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { RegisterRequest, LoginRequest, LoginResponse, AuthUser } from '@/types/auth';

/**
 * Register a new user and organization
 */
export const register = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { email, name, password, organizationName }: RegisterRequest = req.body;

  // Validate password strength
  const passwordValidation = validatePasswordStrength(password);
  if (!passwordValidation.isValid) {
    return next(new AppError(`Password validation failed: ${passwordValidation.errors.join(', ')}`, 400));
  }

  // Check if user already exists
  const existingUser = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (existingUser) {
    return next(new AppError('User with this email already exists', 409));
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Create organization and user in a transaction
  const result = await prisma.$transaction(async (tx) => {
    // Create organization
    const organization = await tx.organization.create({
      data: {
        name: organizationName || `${name}'s Organization`,
        settings: "{}",
      },
    });

    // Create user as admin of the organization
    const user = await tx.user.create({
      data: {
        email: email.toLowerCase(),
        name,
        passwordHash,
        role: UserRole.ADMIN,
        organizationId: organization.id,
      },
      include: {
        organization: {
          select: {
            id: true,
            name: true,
          },
        },
      },
    });

    return { user, organization };
  });

  // Generate tokens
  const tokens = generateTokens(
    result.user.id,
    result.user.organizationId,
    result.user.role
  );

  // Prepare user data
  const userData: AuthUser = {
    id: result.user.id,
    email: result.user.email,
    name: result.user.name,
    role: result.user.role,
    organizationId: result.user.organizationId,
    organizationName: result.user.organization.name,
  };

  // Log successful registration
  logger.info(`New user registered: ${email} for organization: ${result.organization.name}`);

  const response: LoginResponse = {
    user: userData,
    tokens,
  };

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully',
    data: response,
  });
});

/**
 * Login user
 */
export const login = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { email, password }: LoginRequest = req.body;

  // Find user with organization
  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
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
    return next(new AppError('Invalid email or password', 401));
  }

  // Verify password
  const isPasswordValid = await comparePassword(password, user.passwordHash);
  if (!isPasswordValid) {
    logger.warn(`Failed login attempt for user: ${email}`);
    return next(new AppError('Invalid email or password', 401));
  }

  // Generate tokens
  const tokens = generateTokens(
    user.id,
    user.organizationId,
    user.role
  );

  // Update last login
  await prisma.user.update({
    where: { id: user.id },
    data: { lastLogin: new Date() },
  });

  // Prepare user data
  const userData: AuthUser = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    organizationId: user.organizationId,
    organizationName: user.organization.name,
  };

  // Log successful login
  logger.info(`User logged in: ${email}`);

  const response: LoginResponse = {
    user: userData,
    tokens,
  };

  res.status(200).json({
    status: 'success',
    message: 'Login successful',
    data: response,
  });
});

/**
 * Refresh access token
 */
export const refreshToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return next(new AppError('Refresh token is required', 400));
  }

  // Verify refresh token
  const payload = verifyRefreshToken(refreshToken);

  // Find user
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

  if (!user || user.organizationId !== payload.organizationId) {
    return next(new AppError('Invalid refresh token', 401));
  }

  // Generate new tokens
  const tokens = generateTokens(
    user.id,
    user.organizationId,
    user.role
  );

  res.status(200).json({
    status: 'success',
    message: 'Token refreshed successfully',
    data: { tokens },
  });
});

/**
 * Get current user profile
 */
export const getProfile = catchAsync(async (req: Request, res: Response) => {
  // User is attached by auth middleware
  const user = req.user!;

  res.status(200).json({
    status: 'success',
    data: { user },
  });
});

/**
 * Change password
 */
export const changePassword = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user!.id;

  // Get user's current password hash
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { passwordHash: true },
  });

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  // Verify current password
  const isCurrentPasswordValid = await comparePassword(currentPassword, user.passwordHash);
  if (!isCurrentPasswordValid) {
    return next(new AppError('Current password is incorrect', 400));
  }

  // Validate new password strength
  const passwordValidation = validatePasswordStrength(newPassword);
  if (!passwordValidation.isValid) {
    return next(new AppError(`Password validation failed: ${passwordValidation.errors.join(', ')}`, 400));
  }

  // Hash new password
  const newPasswordHash = await hashPassword(newPassword);

  // Update password
  await prisma.user.update({
    where: { id: userId },
    data: { passwordHash: newPasswordHash },
  });

  logger.info(`Password changed for user: ${req.user!.email}`);

  res.status(200).json({
    status: 'success',
    message: 'Password changed successfully',
  });
});

/**
 * Logout (invalidate tokens - placeholder for future token blacklisting)
 */
export const logout = catchAsync(async (req: Request, res: Response) => {
  // In a production system, you would add the tokens to a blacklist
  // For now, we'll just return success and rely on client-side token removal

  logger.info(`User logged out: ${req.user!.email}`);

  res.status(200).json({
    status: 'success',
    message: 'Logged out successfully',
  });
});