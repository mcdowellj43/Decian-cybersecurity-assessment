# Backend Directory Overview

## Architecture
**Node.js/Express API** with TypeScript, serving cybersecurity assessment platform
- **Framework**: Express.js with security-first middleware stack
- **Language**: TypeScript with strict type checking
- **Database**: Prisma ORM with PostgreSQL integration

## Core Structure (18 source files)
- **Entry Point**: `src/index.ts` - Express server with security middleware
- **Controllers**: Agent, Assessment, Report, Auth management (4 files)
- **Routes**: RESTful API endpoints for all resources (4 files)
- **Middleware**: Authentication, error handling, validation (3 files)
- **Utils**: Database, JWT, logging, password utilities (5 files)
- **Types**: TypeScript definitions for authentication (1 file)

## Security Features
- **Authentication**: JWT with refresh tokens, bcryptjs password hashing
- **Protection**: Helmet, CORS, rate limiting (100 req/15min)
- **Validation**: Zod schemas for request/response validation
- **Logging**: Winston structured logging with audit trails

## API Endpoints (14 total)
- **Auth**: `/api/auth` - register, login, logout, password management
- **Agents**: `/api/agents` - CRUD, registration, heartbeat, configuration
- **Assessments**: `/api/assessments` - lifecycle management, results submission
- **Reports**: `/api/reports` - HTML generation, download, listing

## Dependencies
**Production**: Express, Prisma, JWT, bcryptjs, Zod, Winston, security middleware
**Development**: TypeScript, TSX, ESLint, Jest, testing utilities

## Status: 100% Complete
✅ All core API endpoints implemented and functional
✅ Authentication system with role-based access control
✅ Database integration with comprehensive schema