# Patch & Update Status

## What it checks
- **Windows Update configuration** (automatic updates, deferrals, service status)
- **Installed updates** (current build, release ID, pending reboot status)
- **Third-party software updates** (Adobe, Java, browsers, etc.)
- **Windows Defender definitions** (signature freshness, real-time protection status)
- **Automatic update settings** (Microsoft Store, Microsoft Update, Group Policy impact)

## How it checks
- Reads Windows registry keys for Windows Update configuration (`WindowsUpdate\Auto Update`)
- Verifies Windows Update service (`wuauserv`) startup type
- Collects OS build, release ID, and update revision from registry
- Retrieves last update search timestamp and pending reboot flag
- Enumerates installed third-party applications from uninstall registry keys
- Flags end-of-life or vulnerable software (Flash, IE, Silverlight)
- Checks Windows Defender signature versions, last update time, and real-time protection status
- Evaluates automatic app updates (Microsoft Store) and Group Policy overrides

## Scoring & Output
- Each risky configuration or outdated component increases the **risk score**
- Examples:
  - Automatic Updates disabled → **+40**
  - Outdated OS build → **+25**
  - Pending reboot → **+20**
  - Outdated Defender signatures (>3 days) → **+20**
  - End-of-life third-party software (Flash, IE, etc.) → **+30**
- Findings are grouped by category:
  - *Windows Update Configuration*
  - *Installed Updates*
  - *Third-Party Software*
  - *Windows Defender*
  - *Automatic Updates*

## Limitations
- Does not directly query Windows Update servers for available patches
- Software version checks are pattern-based (no full CVE database integration)
- SAM database parsing for detailed lockout/aging is not included
- Time parsing may fail if Windows stores non-standard timestamps

## Remediation Guidance
- Enable fully automatic Windows Updates
- Ensure `wuauserv` is set to Automatic
- Reboot systems with pending updates
- Uninstall or upgrade end-of-life software (Flash, Silverlight, old Java)
- Keep Windows Defender signatures updated within 3 days
- Ensure Microsoft Update is registered for all Microsoft products
- Enforce update policies via Group Policy or endpoint management tools
