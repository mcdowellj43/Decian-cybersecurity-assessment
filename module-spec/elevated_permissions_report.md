# Elevated Permissions Report — Module Documentation

**Module Name:** Elevated Permissions Report  
**Check Type:** `CheckTypeElevatedPermissionsReport`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** High  
**Last Updated:** 2025-09-30

---

## What it checks

- **Administrative accounts**
  - Built‑in *Administrator* account status (enabled/disabled)
  - Size of the local **Administrators** group
  - LSA/UAC hardening for the built‑in Administrator and anonymous access
- **Service account privileges**
  - Services running as **SYSTEM** or **Administrator**
  - Services running under **custom user accounts**
  - Auto‑start services with risky names (e.g., *remote*, *telnet*, *ftp*)
- **Privilege escalation risks**
  - UAC global enablement and prompt behaviors (admins & standard users)
  - Secure desktop for UAC prompts
  - Windows Error Reporting (WER) state
  - **AlwaysInstallElevated** policy
- **User rights & scheduled tasks**
  - LSA auditing toggles relevant to abuse detection
  - Scheduled tasks with privileged‑looking names
- **Local security policy & authentication hardening**
  - (Informational) Password policy note in SAM
  - LM hash storage setting
  - NTLM compatibility level
  - Null session access to shares
  - NTLM minimum client security

---

## How it checks

### 1) Administrative Accounts
- **Built‑in Administrator enabled:**  
  Reads `HKLM\SAM\SAM\Domains\Account\Users\000001F4` → value `F`, flags if bit 1 not set (account enabled).
- **Administrators group membership (count):**  
  Reads `HKLM\SAM\SAM\Domains\Builtin\Aliases\00000220\Members` and counts subkeys.
- **LSA hardening (UAC Admin Approval Mode / Anonymous restrictions):**  
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` →  
  - `FilterAdministratorToken == 0` → Admin Approval Mode **disabled** for built‑in Administrator.  
  - `RestrictAnonymous == 0` → Anonymous access **not restricted**.

### 2) Service Account Privileges
- Enumerates `HKLM\SYSTEM\CurrentControlSet\Services\*`. For each service:  
  - **Account:** `ObjectName` — counts services running as `*system*`/`*administrator*` or under a **custom domain/local account** (`domain\user`).  
  - **Autostart WIN32 service:** `Type == 0x10` and `Start == 2`; flags if the service name contains `remote`, `telnet`, or `ftp`.

### 3) Privilege Escalation Risks
- **UAC system policy:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` →  
  - `EnableLUA == 0` → UAC **disabled**.  
  - `ConsentPromptBehaviorAdmin == 0` → Admins set to **Never notify**.  
  - `ConsentPromptBehaviorUser == 0` → Standard users **auto‑deny** elevation.  
  - `PromptOnSecureDesktop == 0` → UAC prompts **not** on secure desktop.
- **Windows Error Reporting (WER):** `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Disabled`; `0` = enabled.  
- **AlwaysInstallElevated:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated == 1`.

### 4) User Rights Assignments & Tasks
- **LSA audit toggles:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` →  
  - `AuditBaseObjects == 0` (disabled)  
  - `CrashOnAuditFail == 0` (no fail‑closed on audit failure)
- **Scheduled tasks (names only):** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` — counts tasks whose path/name contains `admin`, `elevated`, or `system`.

### 5) Local Security Policy
- **Password policy:** Notes that robust parsing requires SAM database decoding (`HKLM\SAM\SAM\Domains\Account`), which this check does *not* perform.  
- **LM hash storage:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash == 0` → LM hashes **enabled**.  
- **NTLM compatibility:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel < 3` → below recommended.  
- **Null session shares:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictNullSessAccess == 0` → not restricted.  
- **NTLM minimum client security:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec < 0x20080000` → below recommended.

---

## Scoring Logic

- **Built‑in Administrator enabled:** +25  
- **Administrators group > 3 members:** +15 (always reports the count)  
- **Admin Approval Mode disabled for built‑in Admin (`FilterAdministratorToken == 0`):** +20  
- **Anonymous access not restricted (`RestrictAnonymous == 0`):** +15  

- **Per risky auto‑start service (name contains remote/telnet/ftp):** +10  
- **Services running with system‑level accounts > 10:** +15  
- **Services under custom accounts > 5:** +10  

- **UAC disabled (`EnableLUA == 0`):** +35  
- **Admins “Never notify” (`ConsentPromptBehaviorAdmin == 0`):** +25  
- **Standard users auto‑deny (`ConsentPromptBehaviorUser == 0`):** +15  
- **No secure desktop for UAC (`PromptOnSecureDesktop == 0`):** +10  
- **WER enabled (`Disabled == 0`):** +5  
- **AlwaysInstallElevated (`== 1`):** +40  

- **AuditBaseObjects disabled:** +10  
- **CrashOnAuditFail disabled:** +5  
- **Privileged‑looking scheduled tasks:** `count × 5`  

- **Password policy note (SAM parsing required):** +5 (informational)  
- **LM hash storage enabled (`NoLMHash == 0`):** +20  
- **NTLM level below recommended (`LmCompatibilityLevel < 3`):** +15  
- **Null session not restricted (`RestrictNullSessAccess == 0`):** +15  
- **NTLM min client sec below recommended (`NtlmMinClientSec < 0x20080000`):** +10  

**Total risk score is capped at 100** and mapped to a risk level via `DetermineRiskLevel(riskScore)`.

---

## Output Structure

Returns an `AssessmentResult` with category‑grouped findings:

```json
{
  "CheckType": "CheckTypeElevatedPermissionsReport",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Administrative Accounts", "findings": ["..."]},
      {"category": "Service Account Privileges", "findings": ["..."]},
      {"category": "Privilege Escalation Risks", "findings": ["..."]},
      {"category": "User Rights Assignments", "findings": ["..."]},
      {"category": "Security Policy", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Validates and runs on **Windows only**.  
- **Privileges:** **Admin** required (HKLM/HKCU registry reads; services inspection via registry).  
- **I/O Behavior:** Read‑only registry enumeration; string/pattern checks; counting/threshold tests.

---

## Limitations & Edge Cases

- **Registry‑only view:** Does not enumerate live group membership via APIs or PowerShell; counts based on SAM/alias keys may miss domain group nesting.  
- **Service review heuristics:** Flags by **account** and **name substrings**; not a full service permission/DACL audit.  
- **Scheduled tasks heuristic:** Matches on names, not task XML, triggers, or principals.  
- **Password policy parsing:** SAM decoding is out of scope; result includes an informational notice instead.  
- **Domain environments:** Local policies may differ from domain GPO; some keys may be overridden by AD and not reflect effective policy.

---

## Recommended Remediations

- **Accounts & Groups**
  - Disable or tightly control the built‑in **Administrator** account; require strong authentication.  
  - Minimize **Administrators** group membership; use Just‑Enough-Administration (JEA) and role‑based groups.

- **UAC & LSA Hardening**
  - Ensure **UAC enabled** (`EnableLUA=1`), **Admin Approval Mode** on, **Secure Desktop** on.  
  - Restrict anonymous access (`RestrictAnonymous=1`).

- **Services**
  - Run services under **least‑privilege** dedicated accounts; avoid SYSTEM/Administrator where possible.  
  - Review auto‑start services with risky names/functionality; disable or restrict as needed.

- **Policies & AuthN**
  - Disable **AlwaysInstallElevated** on both HKLM/HKCU policy hives.  
  - Set `NoLMHash=1`; raise `LmCompatibilityLevel` (e.g., ≥ **5** in modern domains).  
  - Restrict null sessions and raise `NtlmMinClientSec` to meet enterprise baselines.

- **Monitoring & Auditing**
  - Enable **AuditBaseObjects** as appropriate; decide policy for **CrashOnAuditFail** per risk appetite.  
  - Enumerate scheduled tasks fully (XML/principals/triggers) and remove privileged or unknown tasks.

---

## ATT&CK/CIS Mapping (High‑Level)

- **Valid Accounts (Privileged)** — *MITRE ATT&CK T1078*  
- **Bypass User Account Control** — *T1548.002*  
- **Create or Modify System Process: Windows Service** — *T1543.003*  
- **Scheduled Task/Job: Scheduled Task** — *T1053.005*  
- **Abuse Elevation Control Mechanism (Installer/Policies)** — *Related to AlwaysInstallElevated*

> These mappings are indicative and meant to guide triage and control alignment.

---

## Developer Notes

- Logs start/finish with summary fields: `findings_count`, `risk_score`, `risk_level`.  
- Per‑category findings are appended into a single list and **risk is capped at 100** before risk‑level mapping.

