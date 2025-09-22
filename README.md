# Decian Cybersecurity Assessment Platform

A comprehensive cybersecurity risk assessment platform consisting of a centralized web dashboard and distributed Go-based agents for automated security assessments across Windows environments.

## Architecture

- **Frontend Dashboard**: Next.js 14+ with TypeScript and Tailwind CSS
- **Backend API**: Node.js/Express with TypeScript and Prisma ORM
- **Database**: PostgreSQL
- **Agents**: Go-compiled executables for Windows environments
- **Communication**: Secure TLS-encrypted agent-to-dashboard communication

## Features

### Web Dashboard
- Real-time analytics and risk visualization
- Agent management and deployment
- Comprehensive HTML report generation
- Historical tracking and trend analysis
- Multi-organization support

### Assessment Modules
- Account Policy Analysis
- Domain Controller Security
- DNS Security Assessment
- End-of-Life Software Detection
- Inactive Account Analysis
- Network Protocol Security
- PowerShell Security
- Service Account Privileges
- Password Expiration Analysis
- Windows Feature Security
- Firewall Configuration
- Update Management

## Quick Start

### Prerequisites
- Node.js 18+
- Go 1.21+
- PostgreSQL 14+
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Decian-cybersecurity-assessment
```

2. Install dependencies:
```bash
# Frontend
cd frontend
npm install

# Backend
cd ../backend
npm install

# Agents
cd ../agents
go mod tidy
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Initialize the database:
```bash
cd backend
npx prisma migrate dev
```

5. Start the development servers:
```bash
# Terminal 1 - Backend
cd backend
npm run dev

# Terminal 2 - Frontend
cd frontend
npm run dev
```

### Docker Development

```bash
docker-compose up -d
```

## Project Structure

```
├── frontend/              # Next.js dashboard
├── backend/               # Node.js API server
├── agents/                # Go-based assessment agents
├── shared/                # Shared types and utilities
├── docs/                  # Documentation
├── docker-compose.yml     # Development environment
└── CLAUDE.md             # Comprehensive project specifications
```

## Development

See [CLAUDE.md](./CLAUDE.md) for detailed development guidelines, architecture specifications, and implementation requirements.

## License

Copyright © 2024 Decian. All rights reserved.