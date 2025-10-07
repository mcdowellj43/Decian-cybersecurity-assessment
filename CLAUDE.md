# CLAUDE.md - Cybersecurity Risk Assessment Platform

## CURRENT IMPLEMENTATION PHASE: NETWORK BASED ASSESSMENT MODULES
## IMPORTANT ##
  - as you are going through the feature implementation, reference network-agent-modules.md for what to put in the modules for design, and reference DYNAMIC_MODULE_GUIDE.md for how to build the module so that it fits correctly within the current dynamic module implementation scheme


**PHASE 1 STATUS**: ✅ COMPLETED - Core plugin architecture implemented
- Plugin interfaces defined in `agents/internal/modules/types.go`
- PluginManager system created in `agents/internal/modules/plugin_manager.go`
- Module template and development guide created in `agents/internal/modules/`

**ADDITIONAL DEVELOPMENT RESOURCES**:
- **Module Development Guide**: `agents/internal/modules/MODULE_DEVELOPMENT_GUIDE.md` - Complete step-by-step guide for creating new modules
- **Module Template**: `agents/internal/modules/template_module.go` - Copy-paste template for new modules
- **Plugin Architecture**: All new modules must implement the `ModulePlugin` interface for auto-discovery

# Starting and Stopping the services
# The frontend always runs on port 3000, the backend, on 3001, and prisma DB on 5557
# To start the services, run the ./start-services.sh script
# To stop the services, run the ./delete-services.sh script

## PROJECT OVERVIEW

This is a comprehensive cybersecurity risk assessment platform consisting of a centralized web dashboard and distributed Go-based agents. The platform performs automated security assessments across Windows environments and provides executive-level reporting with actionable insights.

### 📋 QUICK STATUS SUMMARY
- **PHASE**: 1 of 3 (Core Platform Development)
- **PROGRESS**: 98% Complete (Authentication ✅, API Layer ✅, Agent Framework ✅, Download System ✅)
- **NEXT MILESTONE**: Final end-to-end testing and polish
- **CURRENT FOCUS**: Agent deployment and user testing

### Core Architecture Status
- **Frontend Dashboard**: Next.js 15.5.3 with TypeScript ✅ **COMPLETE**
- **Backend API**: Node.js/Express with TypeScript ✅ **COMPLETE**
- **Authentication System**: JWT with role-based access ✅ **COMPLETE**
- **Database Layer**: SQLite with Prisma ORM ✅ **COMPLETE**
- **API Endpoints**: Agent/Assessment/Report management ✅ **COMPLETE**
- **Go Agents**: Windows assessment executables ✅ **COMPLETE** (11 security modules, pure Go implementation)
- **Agent Download System**: Organization-specific config generation ✅ **COMPLETE**
- **Frontend Integration**: API services and hooks ✅ **COMPLETE**
- **Communication**: Secure agent-to-dashboard protocol ✅ **COMPLETE** (TLS 1.3, encryption, HMAC)

---

## IMPLEMENTATION STATUS

### ✅ COMPLETED FOUNDATION (100% Complete)

#### 1. Frontend Dashboard (Next.js 15.5.3)
- Tailwind CSS with project-specific color scheme
- Component library (Button, Card, RiskIndicator, Input)
- Sidebar, Header, Auth-aware layouts
- Login/Register forms with validation
- Zustand store for authentication
- Protected routes and role-based access
- API integration with token refresh
- Dashboard homepage with security metrics
- Successful production builds

#### 2. Backend API (Node.js/Express)
- Core Express server with middleware (helmet, CORS, rate limiting)
- JWT authentication (access/refresh tokens)
- User management endpoints
- bcryptjs password hashing, role-based middleware
- Zod validation schemas with error handling
- Winston logging
- Prisma integration with SQLite
- `.env` configuration

#### 3. Database Layer (SQLite + Prisma)
- Schema with Organizations, Users, Agents, Assessments
- User roles (ADMIN, USER, VIEWER)
- Assessment, Result, Agent, Report models
- AuditLog system for security tracking
- Enums for statuses and risk levels
- Prisma client generated and integrated

### ✅ COMPLETED: CORE API DEVELOPMENT (100% Complete)
- **Agent APIs**: Register, heartbeat, config, CRUD
- **Assessment APIs**: CRUD, results, stop
- **Report APIs**: Generate/download reports, list

### ✅ COMPLETED: GO AGENT FRAMEWORK (100% Complete)

🧪 **Testing & Validation**  
- Built and tested Go executables (14.4MB, Windows PE32)  
- End-to-end registration validated (download, setup, DB registration, JWT auth)  
- Dashboard connectivity confirmed  
- Backend endpoints tested and working  

🎯 **Phase 1 Testing Summary**  
- Agents register, report, and appear in dashboard correctly  
- End-to-end communication validated  
- Local environment tested (Node.js API on 3001, Next.js frontend on 3000, SQLite DB)  

---

#### Enterprise Security Agent Implementation
- Pure Go CLI with cobra framework
- YAML config support
- TLS 1.3 + AES-256-GCM + HMAC
- Plugin-based security modules (11 total)

**Modules Implemented:**
1. Windows Update Check  
2. Misconfiguration Discovery  
3. Weak Password Detection  
4. Data Exposure Check  
5. Phishing Exposure Indicators  
6. Patch & Update Status  
7. Elevated Permissions Report  
8. Excessive Sharing Risks  
9. Password Policy Weakness  
10. Open Service/Port Identification  
11. User Behavior Risk Signals  

---

### ✅ COMPLETED: AGENT DOWNLOAD & DEPLOYMENT SYSTEM

- Organization-specific configs with unique IDs  
- TLS 1.3, encryption, HMAC validation  
- Build-from-source workflow (`go build`)  
- Pre-built binaries planned  
- Frontend integration with download modal, error handling, and copy-to-clipboard  



---

## FUNCTIONAL REQUIREMENTS

### 1. Web Dashboard
- Analytics dashboard
- Agent management
- Report generation
- Data visualization
- Historical tracking

### 2. Agent Functionality (Minimum Checks)
- Misconfiguration Discovery  
- Default & Weak Passwords  
- Data Exposure Check  
- Phishing Indicators  
- Patch Status  
- Elevated Permissions  
- Excessive Sharing Risks  
- Password Policy Weakness  
- Open Services/Ports  
- User Behavior Risk Signals  

### 3. Secure Communication
- TLS 1.3 + cert pinning  
- Mutual TLS / tokens  
- JSON payloads with retries  
- HMAC signatures  
- Rate limiting + resilience  

---

## TECHNICAL SPECIFICATIONS

### Technology Stack
- **Frontend**: Next.js, Tailwind, Zustand, Axios, Jest  
- **Backend**: Node.js/Express, SQLite, Prisma, Winston, Zod, JWT  
- **Go Agent**: Go 1.21+, modular CLI, TLS  

Database schema sample included.  

---

## DESIGN SPECIFICATIONS
- Color scheme (blue-focused, greys, risk-level colors)  
- Typography: Inter + JetBrains Mono  
- Layout: Sidebar, header, cards, responsive  

---

## REPORT SPECIFICATIONS
- Executive summary → Detailed findings → Remediation roadmap  
- Risk visualizations, severity charts, PDF export support  

---

## DEVELOPMENT GUIDELINES
- TypeScript strict mode  
- ESLint + Prettier  
- RESTful API with Swagger  
- Jest testing  
- Secure coding (validation, rate limiting, SQLi prevention)  
- MFA, RBAC, session management  

---

## DEPLOYMENT & OPERATIONS
- Minimum: 4 cores, 8GB RAM, 100GB SSD,  
- Horizontal scaling, Redis caching, monitoring  
- Docker, CI/CD, backup strategy  

---

## SUCCESS CRITERIA
- Dashboard load < 2s  
- Agent run < 5m  
- Report generation < 30s  
- 99.9% uptime  
- >80% code coverage  
 

--

---
# CLAUDE.md – Decian Cybersecurity Assessment Platform

## Project snapshot
- **Monorepo composition:** Next.js dashboard (`frontend`), Express/Prisma API (`backend`), and Go assessment agent (`agents`).
- **Primary goal:** Provide a secure workflow for provisioning agents, queuing Windows security assessments, and presenting results in the dashboard.
- **Current focus:** Rolling out the feature-flagged jobs transport while maintaining legacy assessment endpoints during the transition.

## Repository layout
| Path | Description |
| --- | --- |
| `frontend/` | Next.js 14 application with Tailwind, component library, and hooks for agents/assessments. |
| `backend/` | Express server written in TypeScript, using Prisma against SQLite (dev) and structured logging/error handling. |
| `agents/` | Go 1.21+ CLI (`decian-agent`) providing `setup`, `run`, `register`, and `status` commands plus assessment modules. |
| `shared/` | Shared utilities and types consumed by dashboard/backend (currently minimal). |
| `CLAUDE.md` | This living specification. |

## Architecture updates
- **Jobs-first orchestration:** Assessments now flow through `Job` and `JobResult` records, with agents long-polling `next-jobs` instead of the previous direct assessment submission endpoints.
- **Single enrollment path:** Agents register exclusively via `POST /api/agents/register` using one-time `EnrollmentToken` values, receiving a hashed secret for future authentication.
- **JWT-based transport:** Agents authenticate every queue interaction with short-lived JWTs minted from `POST /api/agents/:id/tokens`, replacing prior static token usage.
- **Dashboard integration:** Assessment scheduling invokes `/enqueue` to populate the queue, and UI components consume job/agent status fields to reflect live execution.

## Key backend capabilities
- **Auth & org scoping**
  - JWT-based user auth with role enforcement (`middleware/auth.ts`).
  - Agent-facing JWT middleware (`middleware/agentAuth.ts`) validating the jobs token claims and binding requests to an `agentId`/`orgId` pair.
- **Feature flagging**
  - `JOBS_API_ENABLED` env var toggles the jobs enrollment + transport path (`config/featureFlags.ts`).
  - All enrollment, token minting, and queue handlers operate exclusively through the jobs architecture.
- **Agent lifecycle APIs** (`routes/agents.ts`)
  - `POST /api/agents/register` verifies one-time enrollment tokens, upserts agents, and returns `{ agentId, agentSecret }` once.
  - `POST /api/agents/:id/tokens` issues short-lived JWTs after validating the Basic credentials against the stored bcrypt hash.
  - Additional CRUD operations cover listing, viewing, updating, deleting agents plus heartbeat updates.
- **Job queue transport** (`routes/jobs.ts`)
  - Long-poll dequeue: `GET /api/agents/:id/next-jobs?wait=30` returns work scoped to the authenticated agent.
  - State transitions: `POST /api/jobs/:jobId/ack`, `POST /api/jobs/:jobId/start`, `PUT /api/jobs/:jobId/results` (idempotent terminal states).
  - Artifact pre-sign stub: `POST /api/jobs/:jobId/artifacts/sign-put` returns mock headers/url for future direct uploads.
- **Assessments & reporting**
  - Dashboard-triggered enqueue: `POST /api/assessments/:assessmentId/enqueue` creates `Job` records for selected agents/modules.
  - Results roll-up updates assessment status and totals; job completion feeds into Prisma transactions.
  - HTML report generation and listing endpoints remain available (`reportController.ts`).

## Data model highlights (Prisma)
- `Agent` now stores `secretHash`, `labels`, and `capacity`; `(orgId, hostname)` uniqueness enforced.
- `EnrollmentToken` records single-use enrollment secrets with expiry + auditing fields.
- `Job` and `JobResult` capture queued work, payloads, and lifecycle metadata with indices on `(orgId, agentId, status)` for fast dequeues.
- Existing `Assessment`, `AssessmentResult`, and `Report` relations integrate with the new queue so assessment progress can be aggregated from job results.
- SQLite is the default datasource (`prisma/dev.db`); migrations live under `backend/prisma/migrations/`.

## Agent CLI capabilities
- **Setup/registration** (`agents/cmd/setup.go`)
  - Prompts for server URL, organization ID, enrollment token, and optional labels.
  - Calls `POST /api/agents/register`, storing the returned `agentId`/`agentSecret` in `%PROGRAMDATA%`/`$APPDATA` depending on OS.
- **Run loop** (`agents/cmd/run.go`)
  - Periodically mints JWTs, long-polls for jobs, performs ACK → START → RESULT transitions, and executes requested assessment modules.
  - Maintains a dedupe cache, exponential backoff with jitter, and refreshes tokens when nearing expiry or on 401s.
  - Assessment jobs dispatch to Go modules located in `agents/internal/modules/`; artifacts are logged as TODO until signed uploads are finalized.
- **Register/status commands** provide non-interactive enrollment and visibility into the saved configuration/state.

## Frontend status
- Authenticated dashboard flows exist for managing agents and assessments; services call into the backend REST API.
- Agents view highlights host status, last check-ins, and pending assessments, with hooks prepared for job-based updates.
- Assessment detail screen consumes backend roll-up data and links to generated HTML reports.

## Observability & tooling
- Backend uses Winston-based structured logging and centralized error responses.
- ESLint (flat config) + TypeScript strictness enforced via `npm run lint:backend` and `npm run typecheck:backend`.
- Agents leverage a lightweight logger abstraction with JSON fields for consistent ingestion.
- Placeholder metrics/cleanup tasks (e.g., TTL job expiration) are outlined but not yet automated cron jobs.


 ## testing the workflow guidelines 

 - when testing the workflow follow the process, sign into the dashboard with mcdowellj@decian.com and Jakeandanna1! as the user/pass
 - if you get a login failed, register the username, password, and organization as Decian
 - then download the agent to the folder C:\users\mcdow\downloads
 - list the commands available for the agent, that are supported
 - register the agent
 - verify the agent registered correctly
 - verify the agent is looking for jobs
 - queue an assessment from the dashboard for the agent you registered
 - verify the assessment ran correctly
 - 
 - need to test the manual workflow and make sure that is rock solid so we can provide proper documentation on how to use it to give to other people. Currently the agent downloads correctly, but need to figure out how/where/if we can access the information we need to properly register the agent.


 Agent Setup and Dashboard Improvements Project

   1. Agent Setup Values Required

  Based on the analysis, here are the required values to set up an agent (once downloaded):

  Required Parameters:
  - --server - Decian API server URL (e.g., "http://localhost:3001")
  - --org-id - Organization identifier (CUID from Organizations table)
  - --enroll-token - One-time enrollment token (32-character hex string)

  Optional Parameters:
  - --hostname - Override hostname (defaults to system hostname)
  - --labels - Key-value labels (e.g., "env=prod,role=web")
  - --capacity - Max concurrent jobs (defaults to 1)
  - --install-service - Install as Windows service (not implemented yet)

  2. Where Values Are Stored

  Backend Database (Prisma/SQLite):
  - Organizations: organizations table with id, name, settings
  - Enrollment Tokens: enrollment_tokens table with tokenHash, orgId, expiresAt, usedAt
  - Agent Registration: agents table stores registered agent details

  Agent Local Storage:
  - Config stored in %PROGRAMDATA%/$APPDATA after successful registration
  - Contains: agentId, agentSecret, server URL, org ID

  Current Backend Implementation:
  - Organizations auto-created during user registration (authController.ts:38-43)
  - Enrollment tokens auto-generated with 15-minute TTL (enrollmentToken.ts:10-31)
  - Tokens returned to frontend after registration/login

● 3. Missing Pieces for Dashboard Visibility

  Currently, the frontend doesn't have easy access to:
  - Organization details and enrollment tokens
  - Organization management (create/view/edit orgs)
  - Current enrollment token status/regeneration
  - Agent setup command generation

  4. Next Steps Implementation Plan

  We need to build:

  Backend APIs:
  - GET /api/organizations - List/view organizations
  - POST /api/organizations - Create organizations
  - GET /api/organizations/:id/enrollment-token - Get current token
  - POST /api/organizations/:id/enrollment-token/regenerate - Create new token

  Frontend Components:
  - Organization management page
  - Agent setup instructions/command generator
  - Enrollment token display with copy-to-clipboard
  - Organization creation form

  