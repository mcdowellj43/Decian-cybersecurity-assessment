# Phishing Exposure Indicators

## Overview
The **Phishing Exposure Indicators** module detects misconfigurations and weak security settings that increase susceptibility to phishing attacks. It inspects browser configurations, email client settings, Windows security features, download protection, and browser extensions.

- **Check Type:** `CheckTypePhishingExposureIndicators`  
- **Platform:** Windows  
- **Default Risk Level:** High  
- **Requires Admin:** No  

---

## Assessment Areas

### 1. Browser Security
- Reviews Internet Explorer zone settings:
  - Identifies weak security levels.
  - Detects if Active Scripting is enabled in risky zones.
- Detects presence of Chrome and Edge, recommending manual checks.

### 2. Email Security
- Reviews Outlook security settings:
  - Detects modified Level 1 attachment blocking.
  - Evaluates macro security levels.
  - Checks whether external content downloads are allowed.
- Detects Windows Mail app presence.

### 3. Windows Security Features
- Verifies Windows Defender SmartScreen status:
  - Disabled or warn-only configurations are flagged.
- Checks Windows Defender real-time protection status.
- Evaluates User Account Control (UAC):
  - Disabled UAC or "Never notify" settings raise risk.

### 4. Download Protection
- Evaluates Windows Attachment Manager policies:
  - Zone information saving.
  - Antivirus scanning of downloads.
- Inspects common download directories (Downloads, Desktop, temp folders):
  - Detects recent executable downloads.

### 5. Browser Extensions
- Reviews Chrome, Edge, and Firefox extension counts:
  - Excessive extensions may indicate risk.
- Detects Firefox extensions via `extensions.json`.

---

## Risk Scoring
- Each weakness adds weighted points.
- Total score capped at 100.
- Risk levels categorized using `DetermineRiskLevel`.

---

## Example Findings
- Internet Explorer Internet Zone allows Active Scripting.  
- Outlook allows automatic download of external content.  
- Windows Defender SmartScreen is disabled.  
- Recent executable download detected in `C:\Users\User\Downloads`.  
- Chrome has 22 extensions installed (high risk).  

---

## Usage
This module highlights phishing exposure risks to help administrators and security teams remediate misconfigurations. It provides actionable findings across browsers, email, and OS-level protections.
