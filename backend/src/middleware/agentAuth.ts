import { Request, Response, NextFunction } from 'express';
import { verifyAgentAccessToken, AgentAuthClaims } from '@/utils/agentJwt';
import { AppError } from './errorHandler';
import { prisma } from '@/utils/database';
import { logger } from '@/utils/logger';

export interface AgentContext {
  agentId: string;
  orgId: string;
  scope: string[];
}

declare module 'express-serve-static-core' {
  interface Request {
    agent?: AgentContext;
  }
}

export const requireAgentJwt = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new AppError('Agent token required', 401));
  }

  const token = authHeader.slice('Bearer '.length).trim();
  try {
    const claims = verifyAgentAccessToken(token);
    await assertAgentActive(claims);
    req.agent = {
      agentId: claims.sub,
      orgId: claims.orgId,
      scope: claims.scope,
    };
    return next();
  } catch (error) {
    logger.warn('Agent token validation failed', { error });
    return next(new AppError('Invalid or expired agent token', 401));
  }
};

const assertAgentActive = async (claims: AgentAuthClaims) => {
  const agent = await prisma.agent.findUnique({ where: { id: claims.sub } });
  if (!agent || agent.orgId !== claims.orgId) {
    throw new Error('agent mismatch');
  }
  if (!agent.secretHash) {
    throw new Error('agent secret missing');
  }
};
