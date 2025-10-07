# Misconfiguration Discovery — Module Documentation

**Module Name:** Misconfiguration Discovery  
**Check Type:** `CheckTypeMisconfigurationDiscovery`  
**Platform:** Windows  
**Requires Admin:** Yes  
**Default Risk Level:** High  
**Last Updated:** 2025-09-30

---

## What it checks

- **Remote Desktop (RDP) exposure**
  - RDP enabled/disabled
  - Network Level Authentication (NLA) requirement
  - Default RDP port usage (3389)
- **Windows Firewall posture**
  - Per-profile state (Domain, Private, Public)
  - Default inbound action (Allow vs. Block)
- **Guest/anonymous account posture**
  - Built-in **Guest** account enabled
  - Anonymous access restrictions via LSA
- **Insecure network protocols**
  - SMBv1 enabled
  - Legacy SSL/TLS (SSL 3.0, TLS 1.0) enabled for servers
- **Risky network share configuration**
  - Administrative shares (C$, ADMIN$) enabled
  - Null session shares configured

---

## How it checks

### 1) Remote Desktop (RDP)
- **RDP enabled:**  
  Reads `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections`; `0` → **enabled**.
- **NLA setting:**  
  `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\UserAuthentication`; `0` → **NLA disabled**.
- **Port number:**  
  `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\Tds\tcp\PortNumber`; `3389` → default port in use.

### 2) Windows Firewall
- For each profile (`Domain`, `Private`, `Public`):  
  `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<Profile>Profile` →  
  - `EnableFirewall == 0` → firewall **disabled** for that profile.  
  - `DefaultInboundAction == 0` → default inbound **Allow** (risky).

### 3) Guest/Anonymous Account
- **Guest account (preferred path):**  
  `HKLM\SAM\SAM\Domains\Account\Users\000001F5\F` — if bit 1 **not** set → **Guest enabled**.  
  *(If SAM path not accessible, falls back to LSA policy check below.)*
- **Anonymous access restriction:**  
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous == 0` → anonymous access **not restricted**.

### 4) Insecure Protocols
- **SMBv1:**  
  `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 == 1` → SMBv1 **enabled**.
- **SSL/TLS:**  
  `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols` →  
  - `TLS 1.0\Server\Enabled == 1` → TLS 1.0 **enabled**.  
  - `SSL 3.0\Server\Enabled == 1` → SSL 3.0 **enabled**.

### 5) Network Shares
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` →  
  - `AutoShareWks == 1` → administrative shares **enabled**.  
  - `NullSessionShares` (null-separated list) → flags configured null session shares if non-empty list.

---

## Scoring Logic

- **RDP enabled:** +25  
- **NLA disabled:** +15  
- **Default RDP port (3389):** +10  

- **Firewall disabled per profile:** +20 each  
- **Default inbound action = Allow per profile:** +15 each  

- **Guest account enabled:** +30  
- **Anonymous access not restricted:** +15  

- **SMBv1 enabled:** +25  
- **TLS 1.0 enabled (Server):** +20  
- **SSL 3.0 enabled (Server):** +30  

- **Administrative shares enabled:** +15  
- **Null session shares configured:** +20  

**Risk score is capped at 100** and mapped to a risk level with `DetermineRiskLevel(riskScore)`.

---

## Output Structure

Returns an `AssessmentResult` grouped by category:

```json
{
  "CheckType": "CheckTypeMisconfigurationDiscovery",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Remote Desktop", "findings": ["..."]},
      {"category": "Firewall", "findings": ["..."]},
      {"category": "User Accounts", "findings": ["..."]},
      {"category": "Network Protocols", "findings": ["..."]},
      {"category": "Network Shares", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Windows only (validated via `runtime.GOOS`).  
- **Privileges:** **Admin** required (SAM/LSA & SCHANNEL registry reads).  
- **I/O Behavior:** Read-only registry enumeration; simple integer/flag checks; string parsing for multi-SZ-like values.

---

## Limitations & Edge Cases

- **Registry-only approach:** Does not confirm network reachability (e.g., open port 3389).  
- **Guest check simplification:** Uses bit inspection of SAM `F` value; detailed SAM parsing is out of scope.  
- **TLS/SSL coverage:** Checks only TLS 1.0 and SSL 3.0 server keys; other protocol variants/ciphers not assessed.  
- **Firewall rules:** Evaluates profile state and default policy, **not** individual inbound rules or per-app exceptions.  
- **Domain/GPO overrides:** Local registry may be superseded by domain policy.

---

## Recommended Remediations

- **RDP Hardening**
  - Disable RDP if not required; if required, enforce **NLA**, change listening port, restrict by firewall, and require MFA/VPN.

- **Firewall Baseline**
  - Ensure firewall **enabled** for all profiles; set **DefaultInboundAction = Block** and allow only required services.

- **Accounts & Anonymous Access**
  - Disable the **Guest** account; ensure `RestrictAnonymous = 1`; audit other built-in accounts.

- **Protocol Hardening**
  - Disable **SMBv1**; remove **SSL 3.0** and **TLS 1.0**; enforce TLS 1.2+ (or TLS 1.3 where supported).

- **Shares**
  - Disable administrative shares where feasible; remove **NullSessionShares**; require SMB signing and enforce least privilege on shares.

---

## ATT&CK/CIS Mapping (High-Level)

- **Exploitation of Remote Services (RDP/SMB)** — *MITRE ATT&CK T1210, T1021.001*  
- **Valid Accounts / Remote Services** — *T1078 / T1021*  
- **Defense Evasion via Legacy Protocols** — *T1562 (contextual)*  
- **CIS Controls:** 4 (Access Control Management), 12 (Network Infrastructure Management), 13 (Network Monitoring & Defense)

> Mappings are indicative and provided for orientation.

---

## Developer Notes

- Logs start/finish and summary fields: `findings_count`, `risk_score`, `risk_level`.  
- Findings are aggregated per category; risk score capped at 100 before mapping to `RiskLevel`.

