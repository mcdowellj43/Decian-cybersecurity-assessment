import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import { Prisma } from '@prisma/client';

export interface EnrollmentTokenCreationResult {
  token: string;
  expiresAt: Date;
}

const ENROLLMENT_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes

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

  return { token, expiresAt };
};
