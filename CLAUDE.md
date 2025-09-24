# CLAUDE.md – Decian Cybersecurity Assessment Platform

## Project snapshot
- **Monorepo composition:** Next.js dashboard (`frontend`), Express/Prisma API (`backend`), and Go assessment agent (`agents`).
- **Primary goal:** Provide a secure workflow for provisioning agents, queuing Windows security assessments, and presenting results in the dashboard.
- **Reference guides:** See [`backend-overview.md`](backend-overview.md) for API specifics and [`agents-overview.md`](agents-overview.md) for CLI/runtime details.
- **Current focus:** Rolling out the jobs transport architecture and ensuring every component speaks the new queue-based protocol.

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

## Outstanding work / next steps
1. **Artifact handling:** Implement real signed URL generation and agent-side upload logic.
2. **Job TTL + cleanup:** Add scheduled tasks to mark `EXPIRED` and purge historical jobs per retention policy.
3. **Frontend UX polish:** Surface job-level progress and labels on the Agents page, integrating new API responses.
4. **Security hardening:** Integrate rate limiting for agent endpoints, rotate enrollment tokens, and introduce asymmetric JWT signing.
5. **Automated testing:** Expand unit/integration coverage for enrollment token validation, job transitions, and agent-client networking.
6. **Deployment readiness:** Document rollout steps for enabling `JOBS_API_ENABLED` in production and migrating existing agents.

---
This document reflects the current state of the repository after introducing the jobs API feature flag, updated Prisma models, backend controllers, and the refactored Go agent client.
