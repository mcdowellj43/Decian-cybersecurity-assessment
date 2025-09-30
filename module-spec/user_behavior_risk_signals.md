# User Behavior Risk Signals — Module Documentation

**Module Name:** User Behavior Risk Signals  
**Check Type:** `CheckTypeUserBehaviorRiskSignals`  
**Platform:** Windows  
**Requires Admin:** No  
**Default Risk Level:** Medium  
**Last Updated:** 2025-09-30

---

## What it checks

- **Browser usage patterns**
  - Presence of Chrome/Edge/Firefox usage artifacts
  - Multiple profiles per browser (potential shadow profiles)
  - Presence of additional browsers (Tor, Opera, Brave, Vivaldi)
  - Indicators for security extensions/manual review
- **Installed applications**
  - Categories of potentially risky apps (P2P, Remote Access, Hacking Tools, System Modification, Privacy/Anonymity, Media)
  - Total installed apps
- **User account behavior**
  - Number of local profiles
  - RunMRU (recent Run commands) presence
  - Security event log sizing
  - Suspicious executables on Desktop
- **File system activity**
  - Recent Downloads activity (executables, archives)
  - Temp directories with unusually high file counts
- **System configuration changes**
  - Hidden files visibility
  - UAC status and prompt level
  - Windows Defender exclusions
  - Firewall profile status

---

## How it checks

### 1) Browser Usage
- **Chrome**
  - Looks for `...\Google\Chrome\User Data\Default\History` to infer usage.
  - Counts profiles found under `...\User Data\` that are named `Default` or start with `Profile*`.
  - Notes presence of `Preferences` to suggest manual review of security settings.
- **Firefox**
  - Presence of `{USERPROFILE}\AppData\Roaming\Mozilla\Firefox\Profiles` indicates usage.
  - Counts profiles (directories) to flag if unusually high.
- **Edge**
  - Looks for `...\Microsoft\Edge\User Data\Default\History` to infer usage.
- **Other browsers**
  - Detects directories for Tor, Opera, Brave, Vivaldi and raises category-specific signals.

### 2) Installed Applications
- Enumerates `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` and `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` for display names and versions.
- Matches app names against curated lists per category (P2P/Remote Access/Hacking Tools/System Modification/Privacy/Media).
- Tallies risky categories to add aggregate risk if many are present.

### 3) User Account Behavior
- Derives current username from `{USERPROFILE}` path and counts sibling profile directories under `C:\Users\` (excluding `Public`/`Default`).
- Checks `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` to infer recent command execution behavior.
- Reviews `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize` to ensure adequate log size (flags if < 100MB).
- Examines `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop` for number of executable files.

### 4) File System Activity
- Walks `{USERPROFILE}\Downloads` for **recent (≤30 days)** files; counts:
  - Executables: `.exe, .msi, .bat, .cmd, .scr`
  - Archives: `.zip, .rar, .7z, .tar`
  - High counts produce findings and risk.
- Scans temp directories (`%TEMP%`, `%TMP%`, `C:\temp`, `C:\tmp`) and flags unusually large file counts.

### 5) System Configuration
- **Explorer view:** `HKCU\...\Explorer\Advanced\Hidden == 1` → Hidden files shown.
- **UAC:** `HKLM\...\Policies\System\EnableLUA == 0` (disabled) and `ConsentPromptBehaviorAdmin == 0` (never notify).
- **Defender exclusions:** Enumerates `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\*` and counts types.
- **Firewall:** `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall == 0` → disabled.

---

## Scoring Logic (high-level)

- **Multiple Chrome profiles (>3):** +8  
- **Multiple Firefox profiles (>2):** +8  
- **Tor Browser detected:** +15; other alternative browsers detected: +3 each  
- **Chrome security prefs manual review:** +3

- **Installed application categories:**  
  - Hacking/Cracking tools: +25 each  
  - Remote access tools: +15 each  
  - P2P/File sharing: +18 each  
  - System modification tools: +12 each  
  - Privacy/Anonymity tools: +10 each  
  - Media/Entertainment: +5 each  
- **>3 risky categories present:** +15 aggregate

- **RunMRU present:** +5  
- **Security log MaxSize < 100MB:** +8  
- **Executables on Desktop >5:** +10

- **Downloads recent files >20:** +8  
- **Recent executable downloads >5:** +15  
- **Recent archive downloads >10:** +5  
- **Temp files in a temp dir >100:** +8

- **Hidden files shown:** +5  
- **UAC disabled:** +25  
- **UAC 'Never notify' for admins:** +20  
- **Windows Defender exclusions present:** +8  
- **Firewall (Standard profile) disabled:** +20  

**Risk score is capped at 100** and mapped to a risk level via `DetermineRiskLevel(riskScore)`.

---

## Output Structure

```json
{
  "CheckType": "CheckTypeUserBehaviorRiskSignals",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Browser Usage", "findings": ["..."]},
      {"category": "Installed Applications", "findings": ["..."]},
      {"category": "User Account Behavior", "findings": ["..."]},
      {"category": "File System Activity", "findings": ["..."]},
      {"category": "System Configuration", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Limitations & Notes

- Heuristic-based matching may produce false positives/negatives; no process execution or browser history parsing is performed.  
- Registry values can be overridden by Group Policy or may be unreadable without elevated permissions in hardened environments.  
- Does not analyze network telemetry or correlate to SIEM events; focuses on local artifacts only.  
- Presence of tools (e.g., Wireshark, nmap) can be benign for IT roles—interpret in context.

---

## Recommended Remediations

- **Browser hardening:** Limit profiles; enforce extension allow-lists; enable Safe Browsing/SmartScreen; disable risky flags.  
- **Application policy:** Remove unapproved remote-access/P2P tools; standardize on approved software; monitor with allow-lists.  
- **Account hygiene:** Increase Security log size; review RunMRU usage; restrict local admin rights.  
- **Downloads hygiene:** Educate users; enable attachment scanning and MOTW enforcement; block dangerous file types via ASR rules.  
- **System hardening:** Keep UAC enabled; minimize Defender exclusions; ensure firewall profiles are enabled and locked via GPO.

---

## Developer Notes

- Aggregates findings by category; caps risk at 100; logs `findings_count`, `risk_score`, `risk_level`.  
- Non-destructive: reads registry and filesystem metadata only.

