# Excessive Sharing & Collaboration Risks — Module Documentation

**Module Name:** Excessive Sharing & Collaboration Risks  
**Check Type:** `CheckTypeExcessiveSharingRisks`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** Medium  
**Last Updated:** 2025-09-30

---

## What it checks

- **Network share exposure & SMB hardening**
  - Administrative shares (e.g., `C$`, `ADMIN$`) enablement
  - Null session shares
  - SMB signing requirements and enablement
  - Volume/number of configured shares
- **File & folder permission exposure (heuristic)**
  - Presence and accessibility of sensitive system/user directories
  - Files present in public locations (potential oversharing)
  - Legacy LanMan share definitions
- **Cloud storage synchronization risks**
  - Presence of local sync folders (OneDrive, Dropbox, Google Drive, Box, iCloud)
  - Sensitive files within sync directories (`*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.sql`, `*.bak`)
  - OneDrive client policy setting (informational)
- **Collaboration & remote access tooling footprint**
  - Installed collaboration apps (Teams, Slack, Zoom, etc.)
  - Installed remote access tools (TeamViewer, AnyDesk, Chrome Remote Desktop, VNC/RDP strings)
- **Windows built‑in sharing features**
  - HomeGroup remnants (legacy)
  - File Sharing Wizard
  - Network discovery configuration presence
  - Nearby sharing (Windows 10+)
  - Windows Media Player (WMP) media sharing

---

## How it checks

### 1) Network Shares
- **SMB Server Parameters:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`  
  - `AutoShareWks == 1` → Administrative shares **enabled**.  
  - `AutoShareServer == 1` → Server administrative shares **enabled**.  
  - `NullSessionShares` (REG_MULTI_SZ-like null‑separated string) → flags configured null session shares.  
  - `RequireSecuritySignature == 0` → SMB signing **not required**.  
  - `EnableSecuritySignature == 0` → SMB signing **disabled**.
- **Defined Shares:** `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares`  
  - Counts shares (excludes names ending with `$` from “user” share count). Reports total and flags high counts.

### 2) File Permissions (Heuristic)
- **Sensitive directories:** `C:\Windows\System32`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\Users`  
  - Basic existence/accessibility check; (full ACL analysis is out of scope in this module).  
- **Public locations:** `C:\Users\Public`, `C:\temp`, `C:\tmp`  
  - Recursively counts files; higher counts imply broader exposure.  
- **LanMan legacy shares:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Network\LanMan` (subkeys presence → note & small risk).

### 3) Cloud Storage Sync
- **Sync roots (from `%USERPROFILE%`):**  
  - OneDrive → `~\OneDrive`  
  - Dropbox → `~\Dropbox`  
  - Google Drive → `~\Google Drive`  
  - Box → `~\Box`  
  - iCloud → `~\iCloudDrive`  
- Flags detected sync folders and scans within each for **sensitive file extensions** (caps reporting to first five names per provider).  
- **OneDrive policy (informational):** `HKCU\SOFTWARE\Microsoft\OneDrive\EnableFileRecycleBin` value logged (note: used as a generic setting indicator; not a risk by itself).

### 4) Collaboration Tools
- **Installed Apps Enumeration:**  
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and  
    `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`  
- Matches `DisplayName` substrings against a list of collaboration tools (Teams, Slack, Zoom, Skype, Webex, GoToMeeting, SharePoint client, Confluence, Jira, Trello, Asana, Notion, etc.).  
- **Remote access tools:** looks for TeamViewer, AnyDesk, Chrome Remote Desktop, VNC, “RDP” strings.

### 5) Windows Sharing Features
- **HomeGroup:** `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\HomeGroup` presence.  
- **File Sharing Wizard:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\SharingWizardOn == 1`.  
- **Network discovery marker:** `HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff` presence logged.  
- **Nearby Sharing:** `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP\NearShareChannelUserAuthzPolicy != 0`.  
- **WMP sharing:** `HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences\EnableMediaSharing == 1`.

---

## Scoring Logic

### Network Shares
- **Administrative shares enabled (`AutoShareWks`/`AutoShareServer`):** +15 each  
- **Null session shares configured:** +25  
- **SMB signing not required (`RequireSecuritySignature == 0`):** +20  
- **SMB signing disabled (`EnableSecuritySignature == 0`):** +15  
- **User shares > 5:** +10 (reports both the non‑admin share count and total shares)

### File Permissions
- **Files in public locations:**  
  - `> 50` files → +15  
  - `> 10` files → +8  
  - `> 0` files → +3  
- **LanMan share subkeys present:** +5

### Cloud Sync
- **Per sensitive file found in any sync folder:** `count × 8` (reports first five names per provider)  
- **More than two active sync apps detected:** +10

### Collaboration / Remote Access
- **Per collaboration app detected:** +5  
- **Per remote access tool detected:** +15  
- **More than five collaboration apps total:** +10

### Windows Sharing Features
- **HomeGroup present:** +8  
- **File Sharing Wizard enabled:** +5  
- **Nearby sharing configured:** +8  
- **WMP media sharing enabled:** +10  

**Total risk score is capped at 100** and mapped with `DetermineRiskLevel(riskScore)`.

---

## Output Structure

Returns an `AssessmentResult` grouped by category:

```json
{
  "CheckType": "CheckTypeExcessiveSharingRisks",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Network Shares", "findings": ["..."]},
      {"category": "File Permissions", "findings": ["..."]},
      {"category": "Cloud Storage Sync", "findings": ["..."]},
      {"category": "Collaboration Tools", "findings": ["..."]},
      {"category": "Windows Sharing Features", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Windows only (validated via `runtime.GOOS`).  
- **Privileges:** **Admin** required (registry access under HKLM/HKCU and filesystem recursion).  
- **I/O Behavior:** Read‑only (registry queries, directory walks, string checks).

---

## Limitations & Edge Cases

- **No ACL analysis:** Directory checks are heuristic; the module does not inspect NTFS ACLs/DACLs or effective permissions.  
- **Share enumeration via registry:** May not include transient or domain‑published shares; excludes admin shares from the “user share” count.  
- **Cloud sync scan scope:** Only provider default folders are scanned; custom locations or multi‑profile setups may be missed.  
- **Collab/remote tooling list:** Substring matching may produce false positives/negatives; does not verify process activity or network exposure.  
- **OneDrive policy value:** `EnableFileRecycleBin` is used as a proxy for “client policy present” and not a direct risk indicator.  
- **Domain policy overrides:** Local registry values may be superseded by GPO and not reflect effective policy.

---

## Recommended Remediations

- **SMB Hardening & Shares**
  - Disable administrative shares where feasible; **require and enable SMB signing**.  
  - Remove **NullSessionShares**; review and minimize user shares; enforce least privilege on share and NTFS permissions.

- **Public Locations & Permissions**
  - Empty or lock down `C:\Users\Public`, `C:\temp`, `C:\tmp`; move sensitive content to protected paths.  
  - Implement periodic scans plus ACL audits for sensitive directories.

- **Cloud Sync Hygiene**
  - Limit the number of active sync providers; segregate confidential data from sync roots.  
  - Remove plaintext secrets/backups from sync folders; adopt secrets management and repository scanning.

- **Collaboration & Remote Access**
  - Standardize on approved tools; uninstall redundant apps.  
  - Restrict or MFA‑gate remote access tools; monitor installations and block unauthorized tools.

- **Windows Features**
  - Remove legacy **HomeGroup** remnants; disable **WMP media sharing** if unused.  
  - Review **Nearby Sharing** and **File Sharing Wizard** policies per environment.

---

## ATT&CK/CIS Mapping (High‑Level)

- **Exfiltration Over Web/Cloud Storage** — *MITRE ATT&CK T1567 / T1537 (contextual)*  
- **Exploitation of Remote Services (SMB)** — *T1210*  
- **Valid Accounts / Remote Services** — *T1078 / T1021*  
- **Exfiltration to Cloud Storage** — *T1567.002*  
- **CIS Controls:** 3 (Data Protection), 4 (Access Control Management), 9 (Email & Web Browser Protections), 12 (Network Infrastructure Management)

> Mappings are indicative to guide policy alignment and triage.

---

## Developer Notes

- Aggregates per‑category findings, caps risk at 100, and computes `RiskLevel`.  
- Logging includes `findings_count`, `risk_score`, `risk_level` on completion.

