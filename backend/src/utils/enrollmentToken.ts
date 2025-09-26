import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { Prisma } from '@prisma/client';
import { logger } from './logger';

export interface EnrollmentTokenCreationResult {
  token: string;
  expiresAt: Date;
}

const ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

// Track active token cleanup timers
const tokenCleanupTimers = new Map<string, NodeJS.Timeout>();

/**
 * Schedule automatic deletion of an enrollment token
 */
const scheduleTokenDeletion = async (tokenHash: string, ttlMs: number): Promise<void> => {
  // Clear any existing timer for this token
  const existingTimer = tokenCleanupTimers.get(tokenHash);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }

  // Schedule deletion
  const timer = setTimeout(async () => {
    try {
      const { prisma } = await import('./database');

      const result = await prisma.enrollmentToken.deleteMany({
        where: {
          tokenHash,
          expiresAt: {
            lt: new Date(),
          },
        },
      });

      if (result.count > 0) {
        logger.info(`Auto-deleted expired enrollment token`, { tokenHash: tokenHash.substring(0, 8) + '...' });
      }

      // Remove timer from tracking
      tokenCleanupTimers.delete(tokenHash);
    } catch (error) {
      logger.error('Error auto-deleting expired enrollment token:', error);
      tokenCleanupTimers.delete(tokenHash);
    }
  }, ttlMs);

  tokenCleanupTimers.set(tokenHash, timer);
};

export const createEnrollmentToken = async (
  tx: Prisma.TransactionClient,
  orgId: string,
  createdBy: string
): Promise<EnrollmentTokenCreationResult> => {
  const token = crypto.randomBytes(16).toString('hex');
  const tokenHash = await bcrypt.hash(token, 10);
  const expiresAt = new Date(Date.now() + ENROLLMENT_TOKEN_TTL_MS);

  await tx.enrollmentToken.create({
    data: {
      orgId,
      tokenHash,
      expiresAt,
      createdBy,
    },
  });

  // Schedule automatic deletion
  scheduleTokenDeletion(tokenHash, ENROLLMENT_TOKEN_TTL_MS);

  logger.info('Enrollment token created with auto-deletion scheduled', {
    orgId,
    expiresAt: expiresAt.toISOString(),
    ttlMinutes: ENROLLMENT_TOKEN_TTL_MS / (60 * 1000),
  });

  return { token, expiresAt };
};

/**
 * Clean up any pending timers (useful for graceful shutdown)
 */
export const clearAllTokenTimers = (): void => {
  tokenCleanupTimers.forEach((timer) => {
    clearTimeout(timer);
  });
  tokenCleanupTimers.clear();
  logger.info('Cleared all enrollment token cleanup timers');
};
