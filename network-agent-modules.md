# Top 10 Single-Agent Network-Safe Modules

This document describes **10 new modules** you can plug into the Decian Agent that run from a single agent on one device (typically a server) and safely probe other devices on the local network. Each module entry contains a short "What it checks" section and a 4–5 sentence "How it works" explanation that is implementation-oriented but network-safe for single-agent deployment.

---

## 1) Port & Service Discovery (Tier A)
**What it checks:**
- Which TCP and UDP ports are open on hosts in the local network and basic service identification (banner/version where available).

**How it works (4–5 sentences):**
The agent performs TCP connect-style probes and conservative UDP probes against a fixed Tier-A list of ports (see exact ports below). For each responsive TCP port it attempts a brief, protocol-aware banner read (e.g., read SSH banner, send `HEAD / HTTP/1.0` to gather HTTP headers) with short read timeouts to avoid blocking. UDP probing is limited to targeted ports with lightweight queries and strict timeouts to avoid noise and long waits. Results are deduplicated and grouped by host, with a small fingerprint (service name, raw banner excerpt, and timestamp) sent back in the finding. The module's risk scoring weights legacy protocols and high-value services heavier and includes metadata about scan timeout, concurrency, and number of hosts scanned.

**Tier-A port lists (exact):**
- **TCP ports:** `22,23,80,88,110,135,137,138,139,143,161,389,443,445,3389,3306,1433,1521,2049,27017,5900,8080,8443`
- **UDP ports:** `53,67,68,69,123,137,138,161,162,500,514,1900,5353,5355`

---

## 2) Operating System Fingerprinting
**What it checks:**
- Estimates of the remote host OS family and version class (e.g., Windows Server 2012-era, embedded Linux) using passive and active fingerprinting signals.

**How it works (4–5 sentences):**
The agent combines passive TCP/TCP-TTL heuristics gathered during port probes (TTL values, TCP window sizes, flag patterns) with lightweight active banner hints to infer an OS family. It does not attempt privileged remote calls — fingerprints are built from observable network characteristics only. Where multiple signals disagree, the module reports a confidence score and the individual evidence points so operators can validate. This helps identify out-of-support operating systems without requiring domain credentials or invasive agents on each endpoint.

---

## 3) Weak Protocol Detection
**What it checks:**
- Presence of insecure, legacy protocols on the network such as Telnet, FTP, SMBv1, and cleartext management protocols.

**How it works (4–5 sentences):**
Using the Port & Service Discovery results as a seed, the agent attempts short, protocol-specific handshakes (for example: send a minimal FTP `USER`/`PASS` probe or observe Telnet negotiation bytes) to confirm protocol presence. The module avoids sending credentials and uses passive/observational responses to determine if the protocol is enabled and whether any server advertises insecure options. If a protocol is known to be unsafe (SMBv1, plain Telnet), the finding is flagged as high severity and includes the evidence and host:port. Rate limiting and strict timeouts ensure the checks are low-impact on production devices.

---

## 4) Shared Folder / SMB Discovery
**What it checks:**
- Enumeration attempts for SMB shares and guest/anonymous access indicators on hosts that expose SMB-related ports.

**How it works (4–5 sentences):**
When SMB-related ports are discovered (e.g., TCP 445/139), the module performs non-destructive SMB enumeration calls to list share names and probe for anonymous access without attempting file reads or writes. It records whether the server allows null-session or guest browsing and collects the share metadata (name, comments) where allowed by protocol. The module explicitly avoids trying to download files or authenticate — it only checks access semantics and presence of shares. Findings indicate shares that are potentially accessible and recommend immediate follow-ups (EDR-assisted file scans or targeted admins) before any deeper content enumeration.

---

## 5) Default Web Page / Device Portal Check
**What it checks:**
- Discovery of web admin consoles, default web pages, or device portals that expose login pages or known default-management UI.

**How it works (4–5 sentences):**
For any host with open web ports (HTTP/HTTPS and alternates from the port scan), the agent issues safe HTTP(S) requests and captures the page title, common header strings, and server response headers. It matches known default-brand strings (camera/router/printer OEM banners) and flags pages that match default-login patterns or contain common administration paths (e.g., `/admin`, `/login`). The module does not attempt login, brute force, or exploit flows — only identification and lightweight banner matching. Findings include the page title, server header, and a recommendation (e.g., change default creds, place behind firewall or require management VLAN).

---

## 6) DNS Hygiene Check
**What it checks:**
- Whether internal DNS servers allow recursion, permit zone transfers (AXFR), or are misconfigured in a way that leaks internal records.

**How it works (4–5 sentences):**
The agent queries configured DNS servers (from DHCP or system resolver settings) using targeted DNS queries: a recursion check, a SAFE zone-transfer attempt (AXFR) only for non-production/public zones, and a lookup of internal hostnames to detect unexpected external resolution. It treats zone transfer attempts conservatively: only performs AXFR against servers that are within the local network and logs the server response (success/fail/refused) as evidence. Recursive openness and successful transfers are flagged as high risk because they may reveal internal topology. The check includes retry/backoff, avoids amplification, and records exact query/response timing for auditing.

---

## 7) RDP & Remote Access Exposure
**What it checks:**
- Presence of remote desktop access services (RDP, VNC, common VPN endpoints) and basic negotiation properties (e.g., RDP NLA support).

**How it works (4–5 sentences):**
On discovery of RDP or other remote-access ports (e.g., 3389, 5900), the agent performs a safe protocol negotiation to determine whether modern protections are required by the server — for RDP this includes checking Network Level Authentication (NLA) negotiation. The module records whether the service requires user authentication prior to session establishment, and captures any banner information without attempting authentication. Exposed remote-access endpoints that lack NLA or are reachable from non-management subnets are flagged and prioritized in the risk score. Recommendations include placing RDP behind a gateway, enabling MFA, or restricting to management VLANs.

---

## 8) Unpatched Service Banner Detection
**What it checks:**
- Service banners and version strings (e.g., `Apache 2.2.15`, `OpenSSH_7.2`) that indicate outdated software likely to contain known vulnerabilities.

**How it works (4–5 sentences):**
After identifying listening services, the agent grabs lightweight banners and headers and normalizes version strings for comparison. The module does not run vulnerability exploits or fingerprint CVEs locally; instead it annotates version strings so the backend can correlate with vulnerability databases. When versions match well-known EOL or old-release thresholds, the finding suggests patching and may include a recommended urgency score. Privacy is respected by only sending the minimal banner text and version metadata rather than full raw responses.

---

## 9) Printer / IoT Device Enumeration
**What it checks:**
- Identification of unmanaged IoT devices and printers by combining SNMP, HTTP, and known port patterns (e.g., 9100, 554, 5000).

**How it works (4–5 sentences):**
The agent probes IoT/printer port fingerprints and issues safe SNMP `get` requests only for public community (if present) to collect a device string (sysDescr) without changing device state. It also fetches HTTP headers or landing pages on typical device ports and matches known firmware or device model strings. These devices are flagged if they lack management VLANs or appear to be using default or highly permissive community strings. Findings include device model, host IP, and recommended mitigations (segmentation, firmware updates, remove public SNMP community).

---

## 10) Basic Traffic Visibility Test
**What it checks:**
- Whether broadcast/multicast query protocols (LLMNR, mDNS, NetBIOS) respond across the LAN and which hosts disclose hostnames or service announcements.

**How it works (4–5 sentences):**
The agent sends controlled, read-only broadcast/multicast queries such as LLMNR and mDNS probes and collects the responses to understand what information is being advertised on the local network. Devices that reply to these queries may leak hostnames, service records, or resource information that an attacker could leverage. The module does not inject payloads — it only listens for and records responses, and correlates responders with prior port/service discoveries for context. The result shows potential information leakage from name-resolution protocols and recommends disabling unnecessary multicast/responder services or segmenting the network.

---

### Notes on Safety and Operational Constraints
- All modules are designed to be **network-safe** for single-agent deployment: no credentialed enumeration, no file downloads, no exploit attempts, and strict timeouts. The agent favors **observation and fingerprinting** over intrusive actions.  
- Scans should be throttled in production; include concurrency, timeout, and host caps in the implementation and make them configurable.  
- Findings that require deeper investigation are explicitly labelled with recommended next steps (EDR-assisted scans, targeted credentialed checks, or penetration tests) rather than performing those invasive actions from the single agent.

---

*Document generated for module development & product collateral.*

