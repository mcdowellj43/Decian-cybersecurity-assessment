# Open Service/Port Identification — Module Documentation

**Module Name:** Open Service/Port Identification  
**Check Type:** `CheckTypeOpenServicePortID`  
**Platform:** Windows  
**Requires Admin:** No  
**Default Risk Level:** Medium  
**Last Updated:** 2025-09-30

---

## What it checks

- **Listening network ports**
  - Common/risky TCP ports (FTP, Telnet, RDP, SQL, SMB, VNC, etc.)
  - Count of “high‑risk” ports listening
- **Running and auto‑start services**
  - Services with names indicating risky functionality (e.g., telnet, ftp, vnc, teamviewer)
  - Volume of auto‑start services
  - Network‑capable Windows services
- **Network service configurations**
  - IIS presence and basic version
  - SQL Server instances and TCP/IP enablement
  - RDP enablement and port (default/custom)
- **Windows built‑in services with exposure risk**
  - Telnet, FTP Server, WWW Publishing, SMTP, SNMP, Remote Registry, etc.
  - Optional Windows features that enable network services (e.g., IIS, FTP, Telnet)
- **Third‑party services**
  - Detection of non‑system services
  - Identification of common third‑party server/remote‑access/peer‑to‑peer software

---

## How it checks

### 1) Listening Ports
- Iterates over a curated list of ports and labels each with a service name and per‑port risk weight (e.g., 23/Telnet = **25**, 445/SMB = **18**, 3389/RDP = **15**, 1433/SQL Server = **20**).  
- **Heuristic method:**  
  - Tries a short TCP connect to `:<port>`; if it succeeds, the port is considered listening.  
  - Otherwise attempts to bind a listener; if binding fails, assumes **something is already listening**.  
- Tracks a count of “high‑risk” ports (weight ≥ 15). If more than 3 are detected, adds a summary finding.

### 2) Running Services
- Reads `HKLM\SYSTEM\CurrentControlSet\Services\*` and evaluates:  
  - **Start type:** `Start == 2` (Automatic), `3` (Manual), `4` (Disabled).  
  - **Risky names:** flags services whose key name contains substrings such as `telnet`, `ftp`, `tftp`, `snmp`, `iis`, `apache`, `nginx`, `mysql`, `postgresql`, `oracle`, `vnc`, `teamviewer`, `anydesk`, `logmein`, `radmin`.  
  - **Type:** if the service `Type` indicates a Win32 service that may accept connections, names are checked again for risky substrings.  
- Adds volume signals (e.g., **auto‑start services > 50**).

### 3) Network Service Configurations
- **IIS:** `HKLM\SOFTWARE\Microsoft\InetStp\MajorVersion` → reports version and recommends secure configuration.  
- **SQL Server:** Enumerates `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\*` instances; for each, checks `...\MSSQLServer\SuperSocketNetLib\Enabled` (TCP/IP).  
- **RDP:** `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections == 0` → enabled; reads `...\Tds\tcp\PortNumber` to report default/custom port.

### 4) Windows Built‑in Services
- Looks up specific service keys (e.g., `TlntSvr`, `MSFTPSVC`, `W3SVC`, `SMTPSVC`, `SNMP`, `RemoteRegistry`, `LanmanServer`, `Spooler`, `IISADMIN`) and inspects `Start`.  
  - **Auto‑start** contributes the full risk weight; **Manual** contributes half.  
- Optional features: enumerates `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OptionalFeatures` and flags features that enable network services (e.g., `IIS-WebServer`, `IIS-FTPServer`, `Telnet*`, `TFTP`, `SimpleTCP`).

### 5) Third‑Party Services
- Uses `ImagePath` to infer non‑system services (paths **outside** `\Windows\` / `\System32\` and not `svchost.exe`).  
- Matches against a list of common third‑party servers, remote‑access tools, and P2P software (Apache, NGINX, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Tomcat, JBoss, WebSphere, VNC, TeamViewer, AnyDesk, LogMeIn, Hamachi, uTorrent, BitTorrent, etc.).  
- Applies additional risk if the service is **not disabled** and particularly if **auto‑start**.

---

## Scoring Logic

### Listening Ports
- Per‑port risk (examples):  
  - **Telnet/23** +25, **SMB/445** +18, **RDP/3389** +15, **SQL/1433** +20, **VNC/5900** +20, **FTP/21** +15, etc.  
- **If ≥ 4 high‑risk ports** are listening: +15 aggregate.  
- Always appends a summary: “Total listening ports detected: _N_”.

### Services
- **Risky auto‑start service (name match):** +12 each.  
- **Network‑capable risky service:** +10 each.  
- **Auto‑start services > 50:** +10 aggregate.  
- Appends counts of risky services and total services.

### Network Service Config
- **IIS detected:** +15 (plus note).  
- **SQL Server instance(s):** +18 aggregate; **per instance TCP/IP enabled:** +8.  
- **RDP enabled:** +15; **RDP default port 3389:** +8; **custom port:** +3.

### Windows Built‑ins
- Per service (examples): Telnet **+30**, FTP Server **+20**, WWW Publishing **+15**, SMTP **+15**, SNMP **+18**, Remote Registry **+22**, Server **+12**, Spooler **+8**, IIS Admin **+15**.  
  - Auto‑start = full weight; Manual = half weight.

### Third‑Party
- **Risky third‑party service not disabled:** +15 (auto‑start) or +8 (manual).  
- **Third‑party services total > 20:** +8 aggregate.  
- Appends totals for detected third‑party and risky third‑party services.

**Total risk score is capped at 100**, then mapped to a risk level via `DetermineRiskLevel(riskScore)`.

---

## Output Structure

Returns an `AssessmentResult` grouped by category:

```json
{
  "CheckType": "CheckTypeOpenServicePortID",
  "Timestamp": "<time>",
  "RiskScore": <0-100>,
  "RiskLevel": "<Low|Medium|High|Critical>",
  "Data": {
    "findings": [
      {"category": "Listening Ports", "findings": ["..."]},
      {"category": "Running Services", "findings": ["..."]},
      {"category": "Network Service Configurations", "findings": ["..."]},
      {"category": "Windows Built-in Services", "findings": ["..."]},
      {"category": "Third-Party Services", "findings": ["..."]}
    ],
    "total_issues": <count_of_categories_with_findings>
  }
}
```

---

## Operational Details & Permissions

- **OS Restriction:** Windows only (validated via `runtime.GOOS`).  
- **Privileges:** Module is marked **Requires Admin: No**; it performs registry reads and network checks that typically **do not require** elevation, though some keys may be unreadable without admin in hardened environments.  
- **I/O Behavior:** Non‑destructive: short TCP connection attempts, bind probes, and registry reads.

---

## Limitations & Edge Cases

- **Port detection heuristic:** The connect/bind approach may misclassify ports on certain hosts; it does **not** enumerate actual listening PIDs or UDP listeners.  
- **No process mapping:** Open ports/services are **not** correlated to owning processes or binaries.  
- **Service name matching:** Substring heuristics can produce false positives/negatives; no verification of service endpoints or firewall state.  
- **SQL/IIS checks:** Presence/config doesn’t confirm network exposure or authentication hardening.  
- **Domain/GPO overrides:** Local registry values may not reflect effective policy.

---

## Recommended Remediations

- **Minimize exposed services:** Disable unused services and close ports; prefer allow‑lists on host firewalls.  
- **Harden remote access & management:** Disable Telnet/FTP; enforce SSH/SFTP, MFA, and jump hosts; restrict RDP by VPN and firewall.  
- **IIS/SQL hardening:** Use least‑privilege service accounts, TLS‑only bindings, updated cipher suites; restrict network access; disable unused protocols.  
- **Remote tools governance:** Standardize on approved remote‑access tools; remove shadow IT tools; enforce logging and MFA.  
- **Monitoring:** Continuously audit port exposure and auto‑start services; alert on new listeners and high‑risk ports.

---

## ATT&CK/CIS Mapping (High‑Level)

- **Exploitation of Remote Services** — *MITRE ATT&CK T1210 / T1021*  
- **Create or Modify System Process: Windows Service** — *T1543.003*  
- **Ingress Tool Transfer / Exfiltration Over Alternative Protocol** — *T1105 / T1048 (contextual)*  
- **CIS Controls:** 12 (Network Infrastructure Management), 13 (Network Monitoring & Defense), 4 (Access Control Management)

> Mappings are indicative to orient defensive alignment.

---

## Developer Notes

- Aggregates per‑category findings; caps risk at 100; computes `RiskLevel` on completion.  
- Logs include `findings_count`, `risk_score`, and `risk_level` for telemetry.

