# Subnet scanning technical plan

## Desired behavior
Allow a single deployed Decian agent to accept an assessment job that names a subnet (up to /24). The agent should:

1. Expand the subnet into discrete IPv4 addresses and probe each candidate host for reachability.
2. Persist the list of active IPs for the life of the job so later retries or modules can reuse it.
3. Run the existing ten security modules against every responsive IP, producing a per-host summary that the backend can aggregate into normal assessment reports.

## Agent-side changes

### Configuration and job inputs
* Teach the job payload parser to expect two new fields: `options.subnet` (CIDR or list) and optional `options.discoveryOverrides` for tuning probe behavior. The hook lives alongside `parseAssessmentPayload` so malformed jobs are rejected before execution.【F:agents/cmd/run.go†L120-L184】

### Discovery workflow
* Add a discovery helper (e.g., `internal/network/discovery.go`) that expands the subnet, sends probes with bounded concurrency, and returns metadata for each responsive host. The helper caches results in memory and optionally on disk so module retries can reuse the same target list instead of re-probing. Default probe ordering should try ARP, then TCP, and finally ICMP to determine reachability.
* Integrate the helper at the start of `executeAssessmentJob`. If no hosts respond, short-circuit the job and submit an informational result indicating the subnet was empty.

### Module execution pipeline
* Update the module runner so modules accept a per-target context. One approach is adding a `Prepare(target TargetContext) error` hook to the `Module` interface or wrapping existing modules in an adapter that injects the IP address before `Validate`/`Execute` run. Runner orchestration then loops over the active hosts, executes all modules for each target, and aggregates the results. This logic builds on the concurrency and timeout handling already present in `RunModules`, but nests it per host so each target runs modules sequentially while multiple targets can execute in parallel.【F:agents/internal/modules/types.go†L15-L55】【F:agents/internal/modules/runner.go†L13-L110】
* Track execution metadata by attaching the target IP to every `AssessmentResult.Data` payload. The runner can inject `data["targetIp"]` as it records module outputs, keeping the backend payload compatible with existing risk scoring.

### Result handling and reporting
* Emit a composite assessment result that includes the discovered host list, per-target module outcomes, and any unreachable addresses. The job summary submitted in `SubmitJobResults` remains a JSON object, so the agent can return `{"discoveredHosts": [...], "moduleResults": [...]}` without changing the REST contract.【F:agents/cmd/run.go†L140-L208】
* Log discovery progress and module failures with the structured logger so operators can audit which IPs were scanned or skipped.【F:agents/internal/modules/runner.go†L31-L109】

## Backend and orchestration updates
* Add UI/API controls that let administrators define subnet scan jobs by choosing a target subnet and, optionally, per-target overrides. The scheduler should send those options in the job payload and continue to assign work to agents advertising a `subnet-scan` capability label.
* Provide aggregation logic that rolls the per-IP results back into the existing reporting model—e.g., one assessment record per host plus an overall subnet summary for dashboards.

## Safety and guardrails
* Enforce a hard limit of 256 targets per job to prevent accidental wide scans. The discovery helper should validate subnets before probing and bail out if the range exceeds the configured maximum.
* Respect per-module timeouts so long-running remote checks cannot starve the agent. Combine these with per-target concurrency caps to keep network utilization predictable.
* Record the discovered IP list in the agent logs and in the job summary so operators can review exactly which hosts were assessed.
