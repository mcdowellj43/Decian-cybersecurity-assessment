import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { logger } from '@/utils/logger';
import { connectDatabase } from '@/utils/database';
import { errorHandler } from '@/middleware/errorHandler';
import { notFoundHandler } from '@/middleware/notFoundHandler';

// Load environment variables
dotenv.config();

// Create Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));

// General middleware
app.use(compression());
app.use(limiter);
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0'
  });
});

// Registration endpoint directly (temporary fix)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, name, password, organizationName } = req.body;

    // Basic validation
    if (!email || !name || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email, name, and password are required'
      });
    }

    // Import prisma and functions here to avoid dependency issues
    const { prisma } = await import('@/utils/database');
    const { hashPassword } = await import('@/utils/password');
    const { generateTokens } = await import('@/utils/jwt');

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({
        status: 'fail',
        message: 'User with this email already exists'
      });
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create organization and user in transaction
    const result = await prisma.$transaction(async (tx) => {
      // Create organization
      const organization = await tx.organization.create({
        data: {
          name: organizationName || `${name}'s Organization`,
          settings: "{}",
        },
      });

      // Create user
      const user = await tx.user.create({
        data: {
          email,
          name,
          passwordHash,
          role: 'ADMIN',
          organizationId: organization.id,
        },
        include: {
          organization: true,
        },
      });

      return { user, organization };
    });

    // Generate tokens
    const tokens = generateTokens(result.user.id, result.organization.id, result.user.role);

    res.status(201).json({
      status: 'success',
      data: {
        user: {
          id: result.user.id,
          email: result.user.email,
          name: result.user.name,
          role: result.user.role,
          organization: {
            id: result.organization.id,
            name: result.organization.name,
          },
        },
        tokens,
      },
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during registration'
    });
  }
});

// Login endpoint directly (temporary fix)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email and password are required'
      });
    }

    // Import required functions
    const { prisma } = await import('@/utils/database');
    const { comparePassword } = await import('@/utils/password');
    const { generateTokens } = await import('@/utils/jwt');

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
      include: {
        organization: true,
      },
    });

    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Check password
    const isPasswordValid = await comparePassword(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({
        status: 'fail',
        message: 'Invalid email or password'
      });
    }

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    // Generate tokens
    const tokens = generateTokens(user.id, user.organizationId, user.role);

    res.json({
      status: 'success',
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          organization: {
            id: user.organization.id,
            name: user.organization.name,
          },
        },
        tokens,
      },
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during login'
    });
  }
});

// API routes
app.get('/api', (req, res) => {
  res.json({
    message: 'Decian Cybersecurity Assessment Platform API',
    version: '1.0.0',
    endpoints: {
      health: '/health',
      api: '/api',
      auth: '/api/auth',
      agents: '/api/agents',
      assessments: '/api/assessments',
      reports: '/api/reports',
      docs: '/api/docs'
    }
  });
});

// Routes will be imported dynamically in startServer

// Error handling middleware will be added after routes are mounted

// Start server
const startServer = async () => {
  try {
    // Connect to database
    await connectDatabase();
    console.log('About to import routes...');

    // Import routes dynamically with better error handling
    const authRoutes = (await import('@/routes/auth')).default;
    console.log('Auth routes imported successfully');

    const agentRoutes = (await import('@/routes/agents')).default;
    console.log('Agent routes imported successfully');

    const assessmentRoutes = (await import('@/routes/assessments')).default;
    console.log('Assessment routes imported successfully');

    const reportRoutes = (await import('@/routes/reports')).default;
    console.log('Report routes imported successfully');

    console.log('All routes imported, mounting...');

    // Direct routes are already registered above

    // API routes
    console.log('Mounting auth routes:', typeof authRoutes);
    app.use('/api/auth', authRoutes);
    console.log('Mounting agent routes:', typeof agentRoutes);
    app.use('/api/agents', agentRoutes);
    console.log('Mounting assessment routes:', typeof assessmentRoutes);
    app.use('/api/assessments', assessmentRoutes);
    console.log('Mounting report routes:', typeof reportRoutes);
    app.use('/api/reports', reportRoutes);

    console.log('All routes mounted successfully, starting server...');

    // Error handling middleware (must be last)
    app.use(notFoundHandler);
    app.use(errorHandler);

    console.log('About to call app.listen on port:', PORT);

    // Start HTTP server
    app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT}`);
      logger.info(`📱 Health check: http://localhost:${PORT}/health`);
      logger.info(`🔌 API endpoint: http://localhost:${PORT}/api`);
      logger.info(`🔐 Auth endpoint: http://localhost:${PORT}/api/auth`);
      logger.info(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  process.exit(0);
});

export default app;