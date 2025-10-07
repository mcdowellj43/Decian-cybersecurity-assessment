# Data Exposure Check — Module Documentation

**Module Name:** Data Exposure Check  
**Check Type:** `CheckTypeDataExposureCheck`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** High  
**Last Updated:** 2025-09-30

---

## What it checks

- **Exposed sensitive files in common/public directories**
  - Keys and certificates (`*.key`, `*.pem`, `*.p12`, `*.pfx`)
  - Database files and backups (`*.sql`, `*.bak`, `*.backup`)
  - Configuration files (`*.config`, `*.ini`, `*.conf`)
  - Logs (`*.log`) and data exports (`*.csv`, `*.xlsx`)
- **Database exposure and weak authentication**
  - Presence of Microsoft SQL Server instances and use of SQL authentication
  - Presence of MySQL installation
- **Cloud storage & API credential exposure**
  - Credential files/directories for AWS, Azure, and Google Cloud
  - Sensitive cloud credentials present in environment variables
- **Browser-saved credentials (password databases)**
  - Chrome/Edge “Login Data” SQLite databases
  - Firefox `logins.json` in profile directories
- **Email configuration exposure**
  - Outlook profiles and local configuration directories
  - Thunderbird configuration directory

---

## How it checks

### 1) Exposed Sensitive Files
- **Locations scanned:** `C:\`, `C:\Users\Public`, `C:\temp`, `C:\tmp`, `C:\inetpub\wwwroot`  
- **Patterns matched:** `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.sql`, `*.bak`, `*.backup`, `*.config`, `*.ini`, `*.conf`, `*.log`, `*.csv`, `*.xlsx`  
- **Method:** Uses `filepath.Glob` for each pattern in each location and flags files deemed “exposed” if their path starts with any of the exposed roots above.  
- **Noise control:** Limits the listed file findings to 20, appending a summary if more are found.

### 2) Database Exposure
- **Microsoft SQL Server:**
  - Reads `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server` to enumerate instances.
  - For each instance, checks `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<instance>\MSSQLServer\LoginMode`.
  - Flags **SQL authentication enabled** when `LoginMode == 2`.
- **MySQL:**
  - Reads `HKLM\SOFTWARE\MySQL AB` to detect presence of MySQL installation.
- **Implementation detail:** Uses `golang.org/x/sys/windows/registry` to query the Windows Registry.

### 3) Cloud Storage Exposure
- **User profile root:** `USERPROFILE` env var is used to construct paths.
- **Credential paths checked:**
  - `~\.aws\credentials`
  - `~\.azure\credentials`
  - `~\.config\gcloud` (directory presence)
  - `~\AppData\Roaming\Microsoft\Azure` (directory presence)
- **Environment variables checked:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`.
- **Method:** Flags presence of the above paths or non-empty env vars as potential exposure.

### 4) Browser Saved Credentials
- **Chrome:** `~\AppData\Local\Google\Chrome\User Data\Default\Login Data`
- **Edge:** `~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data`
- **Firefox:** Walks `~\AppData\Roaming\Mozilla\Firefox\Profiles` and flags any profile containing `logins.json`.
- **Method:** Checks for existence of password DBs; **does not** decrypt or read credentials.

### 5) Email Configuration Exposure
- **Outlook (profiles):** Enumerates `HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles` for profile names.  
  - Flags profile presence and notes that profiles **may contain stored credentials**.
- **Local email client config directories:**
  - `~\AppData\Roaming\Thunderbird`
  - `~\AppData\Local\Microsoft\Outlook`
- **Method:** Registry enumeration (for Outlook) and existence checks for configuration directories.

---

## Scoring Logic

- **Exposed Files:** +15 risk per sensitive file in exposed locations (capped by the 20-result listing limit).  
- **SQL Server present:** +10; **SQL authentication enabled:** +15 (per instance).  
- **MySQL installation detected:** +5.  
- **Cloud credential files present:** +20 each.  
- **Cloud credential env vars present:** +25 each.  
- **Browser password DB present (Chrome/Edge/Firefox):** +15 each.  
- **Outlook profiles found:** +10 total; **per-profile stored creds implied:** +5 each.  
- **Email config directories present:** +8 each.  
- **Total risk score is capped at 100.**

> Final Risk Level is computed via `DetermineRiskLevel(riskScore)` after execution.

---

## Output Structure

The module returns an `AssessmentResult`:

```json
{
  "CheckType": "CheckTypeDataExposureCheck",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {
        "category": "Exposed Files",
        "findings": ["Sensitive file exposed: C:\\..."]
      },
      {
        "category": "Database Exposure",
        "findings": ["Found N SQL Server instances", "SQL Server instance 'X' allows SQL authentication", "MySQL installation detected"]
      },
      {
        "category": "Cloud Storage",
        "findings": ["Cloud credentials found: aws", "Cloud credential in environment variable: AWS_ACCESS_KEY_ID", "..."]
      },
      {
        "category": "Browser Credentials",
        "findings": ["Chrome password database found", "Firefox password database found"]
      },
      {
        "category": "Email Configuration",
        "findings": ["Found N Outlook profiles", "Outlook profile 'Default' may contain stored credentials", "Outlook configuration directory found"]
      }
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Module validates and runs **only on Windows** (`runtime.GOOS` check).  
- **Privileges:** **Admin** required (registry queries under HKLM, filesystem access to system/public dirs).  
- **I/O Behavior:** Read-only checks (registry reads, env var reads, file existence and path scans).  
- **Target Awareness:** Module supports target metadata via `TargetAware` (used by the framework).

---

## Limitations & Edge Cases

- **Scope-limited file search:** Only scans a fixed set of commonly exposed directories; sensitive files outside these locations will not be detected.
- **Credential detection = presence, not exfiltration:** The module flags the existence of credential stores but **does not** decrypt or exfiltrate secrets.
- **Environment variables:** Only the current process environment is inspected; system-wide or service-specific env vars may be missed.
- **Outlook version-specific:** Registry path is hardcoded to **Office 16.0**; older/newer Office versions store profiles under different keys.
- **MySQL detection is coarse:** Presence of `HKLM\SOFTWARE\MySQL AB` indicates installation, not configuration strength.
- **Result volume limiting:** Exposed file findings are truncated to 20 for readability.

---

## Recommended Remediations

- **Relocate/secure sensitive files:** Move keys, configs, and backups out of public or web-root directories; restrict NTFS ACLs; stop serving files from `wwwroot`.
- **Harden databases:** Disable SQL authentication when possible; enforce Windows Authentication; configure strong passwords; restrict network exposure.
- **Protect cloud credentials:** Use managed identities / workload identity federation; remove plaintext keys from disk; vault credentials; scrub env vars from services.
- **Browser password policy:** Prefer enterprise password managers; disable local browser password storage on servers and admin workstations.
- **Email client hygiene:** Remove stale profiles; encrypt local mail stores; avoid storing passwords where not required.
- **Monitoring:** Add detections for creation/modification of credential stores and sensitive file drops in exposed paths.

---

## Mapping (High-Level)

- **Data from Information Repositories — Exfiltration Prep:** *MITRE ATT&CK T1039/T1005 (contextual alignment)*  
- **Credentials In Files / Credentials In Registry:** *ATT&CK T1552.001 / T1552.002 (contextual alignment)*  
- **Exposed Service/Web Root Misuse:** *ATT&CK TA0009 (Collection) / TA0010 (Exfiltration) alignment*

> These mappings are provided for orientation and may vary depending on how findings are ultimately leveraged by an adversary.

---

## Developer Notes

- **Logging:** Uses the framework `logger` for start/finish and summary fields (`findings_count`, `risk_score`, `risk_level`).  
- **Result Building:** Appends per-category findings and aggregates a total; caps risk score at 100.

