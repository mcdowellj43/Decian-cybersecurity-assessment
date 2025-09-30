# Weak Password Detection — Module Documentation

**Module Name:** Weak Password Detection  
**Check Type:** `CheckTypeWeakPasswordDetection`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** High

---

## What it checks

- **Password Policy**
  - Visibility of key password controls (min length/history via SAM/SECURITY hives – summarized)
  - Presence of audit-related controls that influence password security posture
- **Password Expiration**
  - Services running under custom accounts that often have **Password never expires**
- **Blank Passwords**
  - System-wide allowance of blank passwords for console logon
  - LM hash storage (weak/legacy hashing)
- **Default/Stored Passwords**
  - Auto‑logon configuration and plaintext password storage in `Winlogon`
  - Common vendor/service accounts (informational placeholder for deeper enumeration)
- **Password Complexity & Hardening Signals**
  - Logon/UX policies that correlate with weaker practices (e.g., DisableCAD, show last username)
  - Basic audit policy indicators (AuditBaseObjects)

---

## How it checks

### 1) Password Policy
- Opens `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` to read security posture indicators.
- Attempts to read SAM/SECURITY policy locations for password rules:
  - `HKLM\SAM\SAM\Domains\Account` (binary policy in **F** value; needs privileged parsing)
  - `HKLM\SECURITY\Policy\Accounts` (if accessible)
- If direct policy parsing isn’t possible, falls back to an **alternative** check that still surfaces risky **LSA** flags.

**Registry keys referenced**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- `HKLM\SAM\SAM\Domains\Account`
- `HKLM\SECURITY\Policy\Accounts`

### 2) Password Expiration (Service Accounts)
- Enumerates services under `HKLM\SYSTEM\CurrentControlSet\Services`.
- Counts services whose **ObjectName** is a custom/domain account (not LocalSystem/LocalService/NetworkService) — a proxy for accounts that often have *Password never expires*.

**Registry key referenced**
- `HKLM\SYSTEM\CurrentControlSet\Services\<Service>\ObjectName`

### 3) Blank Passwords & LM Hash
- Reads `LimitBlankPasswordUse` from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.
- Reads `NoLMHash` from the same **LSA** key to detect legacy LM hash storage.

**Registry keys referenced**
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash`

### 4) Default / Stored Passwords
- Checks `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` for:
  - `AutoAdminLogon == "1"` → automatic logon enabled
  - Presence of `DefaultPassword` (indicates stored plaintext password)

**Registry key referenced**
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

### 5) Complexity & Hardening Signals
- Reads `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `DisableCAD` — Ctrl+Alt+Del requirement at logon
  - `DontDisplayLastUserName` — username disclosure
- Reads `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AuditBaseObjects` — audit baseline

**Registry keys referenced**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AuditBaseObjects`

---

## Risk scoring (examples based on implementation)

- **Blank passwords allowed (LimitBlankPasswordUse == 0):** +30  
- **LM hash storage enabled (NoLMHash == 0):** +20  
- **Auto‑logon enabled (AutoAdminLogon == "1"):** +25  
  - `DefaultPassword` present (plaintext in registry): **+35 additional**
- **Service accounts using custom logon accounts (>5):** +15  
- **Policy checks that require SAM/SECURITY parsing only:** informational **+5**
- **Audit policy concern (CrashOnAuditFail == 0) in alt path:** +10  
- **DisableCAD == 1:** +10  
- **Show last username at logon (DontDisplayLastUserName == 0):** +5  
- **AuditBaseObjects == 0:** +10

> Final score is capped at **100** and mapped to a risk level via `DetermineRiskLevel`.

---

## Output structure

```json
{
  "CheckType": "CheckTypeWeakPasswordDetection",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Password Policy", "findings": ["..."]},
      {"category": "Password Expiration", "findings": ["..."]},
      {"category": "Blank Passwords", "findings": ["..."]},
      {"category": "Default Passwords", "findings": ["..."]},
      {"category": "Password Complexity", "findings": ["..."]}
    ],
    "total_issues": <count>
  }
}
```

---

## Limitations

- Determining **minimum length/history/complexity** from local policy requires parsing binary data in the SAM/SECURITY hives; this implementation records that requirement but does not parse it.  
- Identification of *default* or *breached* passwords is **not** performed; only strong indicators (auto‑logon, stored password, blank password allowance, LM hash) are flagged.  
- Enumerating actual user accounts and password expiry requires Windows APIs/LDAP (not covered here).  
- Group Policy may override local settings; registry access may need elevation.

---

## Remediation guidance

- **Enforce** password complexity, minimum length, and history via GPO; prefer **NTLMv2** and disable LM hash storage.  
- **Disallow** blank passwords; ensure `LimitBlankPasswordUse = 1`.  
- **Remove** auto‑logon and any `DefaultPassword` values; use secure credential providers.  
- **Rotate** service account passwords regularly; avoid “Password never expires” and adopt **gMSA** where possible.  
- **Harden** logon UX: require Ctrl+Alt+Del and hide last username.  
- **Audit**: enable audit base objects and ensure appropriate security auditing.
