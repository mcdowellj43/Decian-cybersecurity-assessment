import { UserRole } from '@prisma/client';

export interface RegisterRequest {
  email: string;
  name: string;
  password: string;
  organizationName?: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  organizationId: string;
  organizationName: string;
}

export interface LoginResponse {
  user: AuthUser;
  tokens: AuthTokens;
}

export interface JWTPayload {
  userId: string;
  organizationId: string;
  role: UserRole;
  type: 'access' | 'refresh';
}

export interface AuthenticatedRequest extends Request {
  user?: AuthUser;
}