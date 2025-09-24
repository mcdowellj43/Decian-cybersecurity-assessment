import jwt, { SignOptions } from 'jsonwebtoken';
import { UserRole } from '@prisma/client';
import { JWTPayload, AuthTokens } from '@/types/auth';
import { logger } from './logger';

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'fallback-refresh-secret-key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '30d';

/**
 * Generate JWT tokens (access and refresh)
 */
export const generateTokens = (
  userId: string,
  organizationId: string,
  role: UserRole
): AuthTokens => {
  try {
    // Access token payload
    const accessPayload: JWTPayload = {
      userId,
      organizationId,
      role,
      type: 'access',
    };

    // Refresh token payload
    const refreshPayload: JWTPayload = {
      userId,
      organizationId,
      role,
      type: 'refresh',
    };

    // Generate tokens
    const accessTokenOptions: SignOptions = {
      expiresIn: JWT_EXPIRES_IN,
      issuer: 'decian-security',
      audience: 'decian-dashboard',
    } as SignOptions;

    const refreshTokenOptions: SignOptions = {
      expiresIn: JWT_REFRESH_EXPIRES_IN,
      issuer: 'decian-security',
      audience: 'decian-dashboard',
    } as SignOptions;

    const accessToken = jwt.sign(accessPayload, JWT_SECRET, accessTokenOptions);
    const refreshToken = jwt.sign(refreshPayload, JWT_REFRESH_SECRET, refreshTokenOptions);

    // Calculate expiration time in seconds
    const decoded = jwt.decode(accessToken) as any;
    const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  } catch (error) {
    logger.error('Error generating JWT tokens:', error);
    throw new Error('Failed to generate authentication tokens');
  }
};

/**
 * Verify and decode access token
 */
export const verifyAccessToken = (token: string): JWTPayload => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'decian-security',
      audience: 'decian-dashboard',
    }) as JWTPayload;

    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.error('Error verifying access token:', error);
    throw new Error('Invalid or expired access token');
  }
};

/**
 * Verify and decode refresh token
 */
export const verifyRefreshToken = (token: string): JWTPayload => {
  try {
    const decoded = jwt.verify(token, JWT_REFRESH_SECRET, {
      issuer: 'decian-security',
      audience: 'decian-dashboard',
    }) as JWTPayload;

    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    return decoded;
  } catch (error) {
    logger.error('Error verifying refresh token:', error);
    throw new Error('Invalid or expired refresh token');
  }
};

/**
 * Extract token from Authorization header
 */
export const extractTokenFromHeader = (authHeader: string | undefined): string | null => {
  if (!authHeader) {
    return null;
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }

  return parts[1] || null;
};

/**
 * Check if token is expired (without verification)
 */
export const isTokenExpired = (token: string): boolean => {
  try {
    const decoded = jwt.decode(token) as any;
    if (!decoded || !decoded.exp) {
      return true;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    return decoded.exp < currentTime;
  } catch {
    return true;
  }
};