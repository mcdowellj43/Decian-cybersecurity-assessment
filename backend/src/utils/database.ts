import { PrismaClient } from '@prisma/client';
import { logger } from './logger';

// Create a global variable to store the Prisma client
declare global {
  var __prisma: PrismaClient | undefined;
}

// Create Prisma client with logging configuration
const createPrismaClient = () => {
  return new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['error'],
  });
};

// Use global variable in development to prevent too many instances
const prisma = globalThis.__prisma ?? createPrismaClient();

if (process.env.NODE_ENV === 'development') {
  globalThis.__prisma = prisma;
}

// Set up event listeners for logging (only in development)
if (process.env.NODE_ENV === 'development') {
  // Note: Event listeners are simplified due to TypeScript issues
  // In production, we rely on the log configuration above
}

// Test database connection
export const connectDatabase = async () => {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected successfully');
  } catch (error) {
    logger.error('❌ Database connection failed:', error);
    throw error;
  }
};

// Disconnect from database
export const disconnectDatabase = async () => {
  try {
    await prisma.$disconnect();
    logger.info('Database disconnected successfully');
  } catch (error) {
    logger.error('Error disconnecting from database:', error);
    throw error;
  }
};

// Health check for database
export const checkDatabaseHealth = async () => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch (error) {
    logger.error('Database health check failed:', error);
    return false;
  }
};

export { prisma };
export default prisma;