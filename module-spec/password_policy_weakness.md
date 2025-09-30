# Password Policy Weakness — Module Documentation

**Module Name:** Password Policy Weakness  
**Check Type:** `CheckTypePasswordPolicyWeakness`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** High  
**Last Updated:** 2025-09-30

---

## What it checks

- **Local password policy hygiene**
  - LM hash storage enabled
  - NTLM/LanMan compatibility level (LM/NTLM/NTLMv2 enforcement)
  - Blank password restrictions
  - (Informational) SAM policy presence for deeper parsing
- **Account lockout posture (indicators)**
  - Audit policy toggles (CrashOnAuditFail, AuditBaseObjects)
  - Logon UI hardening (don’t display last username; shutdown without logon)
  - (Informational) Lockout threshold/duration note (SAM parsing required)
- **Password complexity posture**
  - Ctrl+Alt+Del requirement
  - Presence/absence of legal notice at logon
  - (Informational) Complexity requirements and password filters (notification packages)
- **Password aging & stored credentials**
  - Services using **custom accounts** (proxy for “password never expires” risk)
  - AutoAdminLogon and presence of plaintext **DefaultPassword** in registry
- **Fine‑grained (domain) policy context**
  - Domain membership and GPO presence indicators
  - Last GPO refresh timestamp
  - Standalone (non‑domain) systems noted

---

## How it checks

### 1) Local Password Policy (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`)
- **LM hash storage:** `NoLMHash == 0` → LM hashes **enabled**.  
- **NTLM level:** `LmCompatibilityLevel` (0..5) interpreted as:  
  - `0–1` → LM and NTLM allowed (insecure)  
  - `2` → NTLM only  
  - `3` → NTLMv2 only  
  - `4` → NTLMv2 required, LM rejected  
  - `5` → NTLMv2 required, LM/NTLM rejected (best)  
- **Blank passwords:** `LimitBlankPasswordUse == 0` → **blank passwords allowed** for console logon.  
- **SAM (informational):** `HKLM\SAM\SAM\Domains\Account` → notes that detailed password policy is stored in binary and would require decoding.

### 2) Account Lockout (Indicators)
- **LSA toggles:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` →  
  - `CrashOnAuditFail == 0` (no fail‑closed on audit failure)  
  - `AuditBaseObjects == 0` (base object auditing disabled)  
- **Logon UI:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` →  
  - `DontDisplayLastUserName == 0` (last username shown)  
  - `ShutdownWithoutLogon == 1` (shutdown allowed pre‑auth)  
- **Note:** Actual **lockout threshold/duration/reset** reside in SAM binary policy; the module records an informational finding.

### 3) Password Complexity
- **CAD requirement:** `DisableCAD == 1` → Ctrl+Alt+Del enforcement **disabled**.  
- **Legal notice:** `LegalNoticeCaption` missing/empty → **no logon banner**.  
- **LSA complexity/filters (informational):**  
  - Adds note that complexity analysis needs LSA secrets.  
  - Reads `Notification Packages` (string) from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` and lists packages if present.

### 4) Password Aging & Stored Credentials
- **Service accounts:** Enumerates `HKLM\SYSTEM\CurrentControlSet\Services\*` and counts services with **custom** `ObjectName` (neither built‑in `LocalSystem/LocalService/NetworkService` nor `NT AUTHORITY/NT SERVICE`).  
  - High counts suggest risk of “password never expires” or weak credential lifecycle for service principals.  
- **Auto logon:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` →  
  - `AutoAdminLogon == "1"` → auto‑logon enabled.  
  - `DefaultPassword` present → plaintext password stored in registry.

### 5) Fine‑Grained / Domain Context
- **Computer name:** `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName` (for context).  
- **Domain membership:** `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Domain`  
  - If present → notes domain membership and that fine‑grained policies may apply.  
  - If absent → notes **standalone** system (local policies apply).  
- **GPO presence:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History` → counts applied GPOs (if any).  
- **Last GPO refresh:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\LastGPOTime`.

---

## Scoring Logic

- **LM hash storage enabled (`NoLMHash == 0`):** +25  
- **NTLM compatibility level:**  
  - `0–1` → +30  
  - `2` → +20  
  - `3` → +10  
  - `4` → +5  
  - `5` → +0  
- **Blank passwords allowed (`LimitBlankPasswordUse == 0`):** +35  
- **SAM analysis note:** +5 (informational)

- **CrashOnAuditFail == 0:** +8  
- **AuditBaseObjects == 0:** +10  
- **Last username displayed:** +8  
- **Shutdown without logon enabled:** +5  
- **(Lockout thresholds require SAM parsing — informational, no extra risk)**

- **CAD disabled (`DisableCAD == 1`):** +10  
- **No legal notice configured:** +5  
- **Complexity/filters informational note:** +5

- **Services using custom accounts:**  
  - `> 10` services → +20  
  - `> 0` services → +8
- **AutoAdminLogon enabled:** +25  
- **DefaultPassword present:** +35

- **Not domain‑joined:** +5  
- **No GPOs detected:** +10  

**Total risk score is capped at 100** and mapped via `DetermineRiskLevel(riskScore)`.

---

## Output Structure

Returns an `AssessmentResult` grouped by category:

```json
{
  "CheckType": "CheckTypePasswordPolicyWeakness",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Local Password Policy", "findings": ["..."]},
      {"category": "Account Lockout Policy", "findings": ["..."]},
      {"category": "Password Complexity", "findings": ["..."]},
      {"category": "Password Aging", "findings": ["..."]},
      {"category": "Fine-Grained Password Policy", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Windows only (validated via `runtime.GOOS`).  
- **Privileges:** **Admin** required (HKLM/SAM/LSA reads).  
- **I/O Behavior:** Read‑only registry queries and string interpretation; no password extraction or decryption.

---

## Limitations & Edge Cases

- **SAM & LSA binary parsing not implemented:** Detailed thresholds (min/max password age, lockout settings, complexity) are **not** decoded; surfaced as informational notes.  
- **Service account inference:** Counts **custom service accounts** as a heuristic; does not verify “password never expires” flags or AD attributes.  
- **Domain/GPO overrides:** Local registry may be overridden by domain policy; keys may not reflect effective settings.  
- **Banner/CAD indicators:** Legal notice/CAD checks are weak signals of security posture, not direct password strength metrics.

---

## Recommended Remediations

- **Hashing & Protocols:** Set `NoLMHash = 1`; raise `LmCompatibilityLevel` to **5** (where compatible).  
- **Blank Passwords:** Ensure `LimitBlankPasswordUse = 1` and enforce minimum password length.  
- **Complexity & CAD:** Enforce password complexity; require **Ctrl+Alt+Del**; deploy a clear **logon banner**.  
- **Lockout:** Define sensible thresholds (e.g., `5` attempts / `15–30` minutes) and monitor for lockout events.  
- **Service Accounts:** Minimize custom service accounts; use gMSAs/Managed Identities; review “password never expires”; rotate credentials.  
- **Auto‑logon:** Disable `AutoAdminLogon`; remove `DefaultPassword`; require MFA where possible.  
- **GPO Hygiene:** Ensure domain membership where intended; verify GPOs are applied and current.

---

## ATT&CK/CIS Mapping (High‑Level)

- **Valid Accounts / Brute Force** — *MITRE ATT&CK T1078 / T1110*  
- **OS Credential Dumping (hash weaknesses)** — *T1003 (contextual)*  
- **Modify Authentication Process / Registry** — *T1112 (contextual)*  
- **CIS Controls:** 4 (Access Control Management), 5 (Account Management), 6 (Access Control Monitoring), 16 (Application Software Security)

> Mappings are indicative and help guide policy alignment and triage.

---

## Developer Notes

- Aggregates per‑category findings, caps risk at 100, then computes `RiskLevel`.  
- Logs include `findings_count`, `risk_score`, `risk_level` on completion.

