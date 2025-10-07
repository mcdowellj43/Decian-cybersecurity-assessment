'use client';

import { useState } from 'react';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import {
  Shield,
  Key,
  Database,
  Mail,
  Download,
  Users,
  Share2,
  Lock,
  Network,
  Eye,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Clock,
  Info,
  Code,
  Settings,
  Server,
  Globe,
  Wifi,
  Monitor,
  Router,
  Search,
  FileSearch,
  Activity,
  Radio,
  Printer
} from 'lucide-react';

type ModuleInfo = {
  name: string;
  checkType: string;
  description: string;
  riskLevel: 'HIGH' | 'MEDIUM' | 'LOW';
  requiresAdmin: boolean;
  icon: any;
  details: string[];
  useCases: string[];
  complianceFrameworks: string[];
  technicalDetails?: {
    whatItChecks: string[];
    howItChecks: {
      section: string;
      details: string[];
    }[];
    limitations?: string[];
    remediation?: string[];
  };
};

const modules: ModuleInfo[] = [
  {
    name: 'Misconfiguration Discovery',
    checkType: 'MISCONFIGURATION_DISCOVERY',
    description: 'Scans for risky system configurations that could expose the organization to security threats.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Shield,
    details: [
      'Open RDP (Remote Desktop Protocol) connections',
      'Permissive firewall rules',
      'Guest account configurations',
      'Insecure protocol usage',
      'Registry misconfigurations'
    ],
    useCases: [
      'Initial security assessments',
      'Compliance audits (SOC 2, ISO 27001)',
      'Post-deployment security validation',
      'Regular security hygiene checks'
    ],
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'RDP enabled/disabled and Network Level Authentication (NLA) requirement',
        'Windows Firewall state per profile (Domain, Private, Public) and default inbound actions',
        'Built-in Guest account status and anonymous access restrictions',
        'SMBv1 enabled and legacy SSL/TLS (SSL 3.0, TLS 1.0) server configurations',
        'Administrative shares (C$, ADMIN$) and null session share configurations'
      ],
      howItChecks: [
        {
          section: 'Remote Desktop (RDP)',
          details: [
            'Checks port 3389 running on the device',
            'Reads HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\fDenyTSConnections registry key',
            'Verifies Network Level Authentication via UserAuthentication registry value',
            'Identifies default vs custom RDP port configuration'
          ]
        },
        {
          section: 'Windows Firewall',
          details: [
            'Checks firewall rules in Windows Defender using PowerShell scripts',
            'Reads EnableFirewall and DefaultInboundAction for each profile',
            'Evaluates HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy registry paths'
          ]
        },
        {
          section: 'User Accounts',
          details: [
            'Checks account permissions in Windows computer management/group policy',
            'Examines Guest account status via HKLM\\SAM\\SAM\\Domains\\Account\\Users registry',
            'Verifies anonymous access restrictions through LSA registry settings'
          ]
        },
        {
          section: 'Network Protocols',
          details: [
            'Checks for SMB, Telnet, FTP active by probing ports 445, 23, and 21',
            'Verifies SMBv1 status via HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters',
            'Checks SSL/TLS protocol enablement in SCHANNEL registry keys'
          ]
        },
        {
          section: 'Registry Security',
          details: [
            'Checks if registry keys can be edited by non-admin users',
            'Verifies administrative share configurations',
            'Examines null session share settings and access restrictions'
          ]
        }
      ],
      limitations: [
        'Registry-only approach - does not confirm network reachability',
        'Does not evaluate individual firewall rules or per-app exceptions',
        'Local registry may be superseded by domain policy',
        'Guest check uses simplified bit inspection of SAM F value'
      ],
      remediation: [
        'Disable RDP if not required; if required, enforce NLA and change listening port',
        'Ensure firewall enabled for all profiles with DefaultInboundAction = Block',
        'Disable Guest account and ensure RestrictAnonymous = 1',
        'Disable SMBv1 and remove SSL 3.0/TLS 1.0 protocols',
        'Disable administrative shares and remove NullSessionShares where feasible'
      ]
    }
  },
  {
    name: 'Weak Password Detection',
    checkType: 'WEAK_PASSWORD_DETECTION',
    description: 'Identifies accounts using vendor defaults or passwords found in breach dictionaries.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Key,
    details: [
      'Default vendor passwords',
      'Common weak passwords',
      'Passwords found in known breach databases',
      'Account password policies',
      'Service account password strength'
    ],
    useCases: [
      'Password security audits',
      'Compliance with password standards',
      'Identity security assessments',
      'Pre-breach vulnerability identification'
    ],
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Password policy visibility via SAM/SECURITY hives (minimum length, history, complexity)',
        'Services running under custom accounts with "Password never expires" setting',
        'System-wide allowance of blank passwords and LM hash storage',
        'Auto-logon configuration and plaintext password storage in Winlogon',
        'Password complexity and hardening signals via logon/UX policies'
      ],
      howItChecks: [
        {
          section: 'Password Policy',
          details: [
            'Opens HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa for security indicators',
            'Attempts to read SAM/SECURITY policy locations for password rules',
            'Reads HKLM\\SAM\\SAM\\Domains\\Account for binary policy data',
            'Falls back to alternative LSA flag checks if direct policy parsing unavailable'
          ]
        },
        {
          section: 'Service Account Expiration',
          details: [
            'Enumerates services under HKLM\\SYSTEM\\CurrentControlSet\\Services',
            'Counts services with custom/domain ObjectName accounts',
            'Identifies accounts likely configured with "Password never expires"'
          ]
        },
        {
          section: 'Blank Passwords & LM Hash',
          details: [
            'Reads LimitBlankPasswordUse from LSA registry key',
            'Checks NoLMHash setting to detect legacy LM hash storage',
            'Verifies console logon blank password allowance'
          ]
        },
        {
          section: 'Stored Passwords',
          details: [
            'Checks HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
            'Detects AutoAdminLogon = "1" for automatic logon',
            'Identifies presence of DefaultPassword (plaintext storage)'
          ]
        },
        {
          section: 'Security Hardening',
          details: [
            'Reads DisableCAD (Ctrl+Alt+Del requirement) policy',
            'Checks DontDisplayLastUserName (username disclosure) setting',
            'Verifies AuditBaseObjects audit baseline configuration'
          ]
        }
      ],
      limitations: [
        'Binary SAM/SECURITY policy parsing requires privileged access',
        'Does not identify actual default or breached passwords',
        'Cannot enumerate user accounts and password expiry without Windows APIs',
        'Group Policy may override local registry settings'
      ],
      remediation: [
        'Enforce password complexity, minimum length, and history via GPO',
        'Disallow blank passwords: LimitBlankPasswordUse = 1',
        'Remove auto-logon and DefaultPassword values',
        'Rotate service account passwords regularly and adopt gMSA',
        'Require Ctrl+Alt+Del and hide last username at logon'
      ]
    }
  },
  {
    name: 'Data Exposure Check',
    checkType: 'DATA_EXPOSURE_CHECK',
    description: 'Scans for exposed sensitive files, cloud storage misconfigurations, and unencrypted data stores.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Database,
    details: [
      'Unencrypted sensitive files',
      'Cloud storage misconfigurations',
      'Database exposure risks',
      'File permission misconfigurations',
      'Backup security'
    ],
    useCases: [
      'Data protection compliance (GDPR, CCPA)',
      'Cloud security assessments',
      'File system security audits',
      'Data classification validation'
    ],
    complianceFrameworks: ['GDPR', 'CCPA', 'SOC 2', 'NIST CSF'],
    technicalDetails: {
      whatItChecks: [
        'Exposed sensitive files in common/public directories (keys, certificates, database files)',
        'Microsoft SQL Server instances and use of SQL authentication',
        'Cloud storage credential files for AWS, Azure, and Google Cloud',
        'Browser-saved credential databases (Chrome, Edge, Firefox)',
        'Email configuration exposure (Outlook profiles, Thunderbird)'
      ],
      howItChecks: [
        {
          section: 'Exposed Sensitive Files',
          details: [
            'Scans C:\\, C:\\Users\\Public, C:\\temp, C:\\tmp, C:\\inetpub\\wwwroot',
            'Searches for *.key, *.pem, *.p12, *.pfx, *.sql, *.bak, *.backup files',
            'Identifies *.config, *.ini, *.conf, *.log, *.csv, *.xlsx in exposed locations',
            'Uses filepath.Glob for pattern matching and limits results to 20 files'
          ]
        },
        {
          section: 'Database Exposure',
          details: [
            'Reads HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server for instances',
            'Checks LoginMode registry key for each instance (LoginMode == 2 = SQL auth)',
            'Detects MySQL installation via HKLM\\SOFTWARE\\MySQL AB registry key',
            'Uses golang.org/x/sys/windows/registry for Windows Registry queries'
          ]
        },
        {
          section: 'Cloud Storage',
          details: [
            'Checks user profile for ~/.aws/credentials, ~/.azure/credentials',
            'Looks for ~/.config/gcloud and ~/AppData/Roaming/Microsoft/Azure directories',
            'Scans environment variables: AWS_ACCESS_KEY_ID, AZURE_CLIENT_ID, GOOGLE_APPLICATION_CREDENTIALS',
            'Flags presence of credential paths or non-empty environment variables'
          ]
        },
        {
          section: 'Browser Credentials',
          details: [
            'Locates Chrome Login Data: ~/AppData/Local/Google/Chrome/User Data/Default/',
            'Finds Edge Login Data: ~/AppData/Local/Microsoft/Edge/User Data/Default/',
            'Walks Firefox profiles: ~/AppData/Roaming/Mozilla/Firefox/Profiles for logins.json',
            'Checks existence of password databases without decryption'
          ]
        },
        {
          section: 'Email Configuration',
          details: [
            'Enumerates HKCU\\SOFTWARE\\Microsoft\\Office\\16.0\\Outlook\\Profiles',
            'Checks ~/AppData/Roaming/Thunderbird and ~/AppData/Local/Microsoft/Outlook',
            'Identifies configuration directories that may contain stored credentials'
          ]
        }
      ],
      limitations: [
        'Limited to fixed set of commonly exposed directories',
        'Detects credential store presence, not actual secrets',
        'Only inspects current process environment variables',
        'Outlook detection hardcoded to Office 16.0 version',
        'Results limited to 20 files for readability'
      ],
      remediation: [
        'Move sensitive files out of public/web-root directories with proper NTFS ACLs',
        'Disable SQL authentication when possible; enforce Windows Authentication',
        'Use managed identities for cloud; remove plaintext credentials from disk',
        'Implement enterprise password managers; disable local browser storage',
        'Remove stale email profiles and encrypt local mail stores'
      ]
    }
  },
  {
    name: 'Phishing Exposure Indicators',
    checkType: 'PHISHING_EXPOSURE_INDICATORS',
    description: 'Detects browser configurations, email settings, and security features that increase phishing susceptibility.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Mail,
    details: [
      'Browser security settings',
      'Email client configurations',
      'Anti-phishing protections',
      'Security awareness indicators',
      'URL filtering effectiveness'
    ],
    useCases: [
      'Security awareness assessments',
      'Email security evaluations',
      'Browser security audits',
      'Phishing readiness testing'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Browser security settings and anti-phishing protections',
        'Email client configurations and security features',
        'URL filtering effectiveness and security awareness indicators'
      ],
      howItChecks: [
        {
          section: 'Browser Security',
          details: [
            'Examines browser security settings for phishing protection',
            'Checks for enabled anti-malware and anti-phishing features',
            'Verifies secure browsing and download protection settings'
          ]
        }
      ]
    }
  },
  {
    name: 'Patch & Update Status',
    checkType: 'PATCH_UPDATE_STATUS',
    description: 'Evaluates Windows Update configuration, missing patches, and third-party software update status.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Download,
    details: [
      'Windows Update settings',
      'Missing security patches',
      'Third-party software updates',
      'Update deployment policies',
      'Critical vulnerability exposure'
    ],
    useCases: [
      'Vulnerability management',
      'Patch compliance verification',
      'Security update tracking',
      'Risk assessment for unpatched systems'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls', 'SOC 2']
  },
  {
    name: 'Elevated Permissions Report',
    checkType: 'ELEVATED_PERMISSIONS_REPORT',
    description: 'Identifies accounts with administrative privileges, service accounts with high privileges, and privilege escalation risks.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Users,
    details: [
      'Administrative account usage',
      'Service account privileges',
      'Privilege escalation paths',
      'User access rights',
      'Group membership analysis'
    ],
    useCases: [
      'Privilege access management (PAM)',
      'Least privilege compliance',
      'Identity governance assessments',
      'Access control audits'
    ],
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Built-in Administrator account status and local Administrators group size',
        'Services running as SYSTEM, Administrator, or custom user accounts',
        'UAC global enablement, prompt behaviors, and secure desktop settings',
        'LSA auditing toggles and scheduled tasks with privileged names',
        'Password policy, LM hash storage, NTLM compatibility, and client security settings'
      ],
      howItChecks: [
        {
          section: 'Administrative Accounts',
          details: [
            'Reads HKLM\\SAM\\SAM\\Domains\\Account\\Users\\000001F4 value F for Administrator status',
            'Counts HKLM\\SAM\\SAM\\Domains\\Builtin\\Aliases\\00000220\\Members subkeys',
            'Checks FilterAdministratorToken and RestrictAnonymous in LSA registry',
            'Examines Admin Approval Mode settings for built-in Administrator'
          ]
        },
        {
          section: 'Service Account Privileges',
          details: [
            'Enumerates HKLM\\SYSTEM\\CurrentControlSet\\Services for ObjectName accounts',
            'Counts services running as system/administrator or custom domain/local accounts',
            'Identifies auto-start services (Type=0x10, Start=2) with risky names',
            'Flags services containing "remote", "telnet", or "ftp" in names'
          ]
        },
        {
          section: 'Privilege Escalation Risks',
          details: [
            'Checks UAC system policy: EnableLUA, ConsentPromptBehaviorAdmin/User',
            'Verifies PromptOnSecureDesktop setting for UAC prompts',
            'Examines Windows Error Reporting disabled status',
            'Detects AlwaysInstallElevated policy in installer settings'
          ]
        },
        {
          section: 'Security Policy',
          details: [
            'Reads NoLMHash setting to detect legacy LM hash storage',
            'Checks LmCompatibilityLevel for NTLM compatibility settings',
            'Verifies RestrictNullSessAccess for null session restrictions',
            'Examines NtlmMinClientSec for minimum client security requirements'
          ]
        }
      ],
      limitations: [
        'Registry-only view - does not enumerate live group membership via APIs',
        'Service review uses heuristics based on account names and substrings',
        'Scheduled tasks matched on names only, not XML/triggers/principals',
        'Local policies may differ from domain GPO in domain environments'
      ],
      remediation: [
        'Disable or tightly control built-in Administrator account',
        'Minimize Administrators group membership; use Just-Enough-Administration',
        'Ensure UAC enabled with Admin Approval Mode and Secure Desktop',
        'Run services under least-privilege dedicated accounts',
        'Disable AlwaysInstallElevated and set NoLMHash=1'
      ]
    }
  },
  {
    name: 'Excessive Sharing & Collaboration Risks',
    checkType: 'EXCESSIVE_SHARING_RISKS',
    description: 'Analyzes network shares, file permissions, cloud storage sync, and collaboration tool configurations.',
    riskLevel: 'MEDIUM',
    requiresAdmin: true,
    icon: Share2,
    details: [
      'Network share permissions',
      'File sharing configurations',
      'Cloud storage synchronization',
      'Collaboration tool settings',
      'Data access controls'
    ],
    useCases: [
      'Data governance assessments',
      'Collaboration security reviews',
      'File sharing policy compliance',
      'Cloud security evaluations'
    ],
    complianceFrameworks: ['GDPR', 'CCPA', 'SOC 2'],
    technicalDetails: {
      whatItChecks: [
        'Network share permissions and file sharing configurations',
        'Cloud storage synchronization settings',
        'Collaboration tool configurations and data access controls'
      ],
      howItChecks: [
        {
          section: 'Network Shares',
          details: [
            'Enumerates shared folders and permission settings',
            'Checks for overly permissive share access',
            'Examines cloud sync folder configurations'
          ]
        }
      ]
    }
  },
  {
    name: 'Password Policy Weakness',
    checkType: 'PASSWORD_POLICY_WEAKNESS',
    description: 'Analyzes domain and local password policies for compliance with security best practices.',
    riskLevel: 'HIGH',
    requiresAdmin: true,
    icon: Lock,
    details: [
      'Password complexity requirements',
      'Password age policies',
      'Account lockout settings',
      'Password history enforcement',
      'Multi-factor authentication requirements'
    ],
    useCases: [
      'Identity security assessments',
      'Compliance audits (NIST, CIS)',
      'Password policy optimization',
      'Authentication security reviews'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls', 'SOC 2']
  },
  {
    name: 'Open Service/Port Identification',
    checkType: 'OPEN_SERVICE_PORT_ID',
    description: 'Identifies listening services, open ports, and network service configurations that may present security risks.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Network,
    details: [
      'Listening network services',
      'Open TCP/UDP ports',
      'Service configurations',
      'Network exposure risks',
      'Unnecessary service discovery'
    ],
    useCases: [
      'Network security assessments',
      'Attack surface analysis',
      'Service hardening',
      'Network segmentation validation'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Common/risky TCP ports (FTP, Telnet, RDP, SQL, SMB, VNC) and high-risk port counts',
        'Running and auto-start services with risky functionality names',
        'IIS presence/version, SQL Server instances, and RDP enablement/port configuration',
        'Windows built-in services with exposure risk (Telnet, FTP, SMTP, SNMP)',
        'Third-party services and non-system services with network capabilities'
      ],
      howItChecks: [
        {
          section: 'Listening Ports',
          details: [
            'Iterates over curated list of ports with risk weights (Telnet/23=25, SMB/445=18, etc.)',
            'Attempts short TCP connect to each port; success indicates listening service',
            'Falls back to bind attempt - failure suggests something already listening',
            'Tracks count of "high-risk" ports (weight ≥ 15) and flags if >3 detected'
          ]
        },
        {
          section: 'Running Services',
          details: [
            'Reads HKLM\\SYSTEM\\CurrentControlSet\\Services for Start type evaluation',
            'Identifies Start=2 (Automatic), Start=3 (Manual), Start=4 (Disabled)',
            'Flags services with risky names: telnet, ftp, snmp, iis, mysql, vnc, teamviewer',
            'Checks service Type for Win32 services that may accept connections'
          ]
        },
        {
          section: 'Network Service Configurations',
          details: [
            'Checks HKLM\\SOFTWARE\\Microsoft\\InetStp\\MajorVersion for IIS presence',
            'Enumerates SQL Server instances under Microsoft SQL Server registry',
            'Verifies RDP via Terminal Server\\fDenyTSConnections registry key',
            'Reads RDP port from Tds\\tcp\\PortNumber (default 3389 vs custom)'
          ]
        },
        {
          section: 'Built-in Services',
          details: [
            'Looks up specific service keys: TlntSvr, MSFTPSVC, W3SVC, SMTPSVC, SNMP',
            'Checks RemoteRegistry, LanmanServer, Spooler, IISADMIN service status',
            'Applies full risk weight for auto-start, half weight for manual',
            'Enumerates optional Windows features that enable network services'
          ]
        },
        {
          section: 'Third-Party Services',
          details: [
            'Uses ImagePath to identify non-system services (outside \\Windows\\ \\System32\\)',
            'Excludes svchost.exe and identifies custom service executables',
            'Matches against common third-party servers and remote-access tools',
            'Flags Apache, NGINX, MySQL, VNC, TeamViewer, AnyDesk, P2P software'
          ]
        }
      ],
      limitations: [
        'Connect/bind approach may misclassify ports on certain hosts',
        'Does not enumerate actual listening PIDs or UDP listeners',
        'No correlation between open ports/services and owning processes',
        'Local registry values may not reflect effective domain policy'
      ],
      remediation: [
        'Disable unused services and close unnecessary ports',
        'Prefer allow-lists on host firewalls for exposed services',
        'Disable Telnet/FTP; enforce SSH/SFTP with MFA and jump hosts',
        'Harden IIS/SQL with least-privilege accounts and TLS-only bindings',
        'Remove shadow IT remote-access tools and standardize on approved solutions'
      ]
    }
  },
  {
    name: 'User Behavior Risk Signals',
    checkType: 'USER_BEHAVIOR_RISK_SIGNALS',
    description: 'Analyzes user activity patterns, installed applications, browser usage, and system configurations.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Eye,
    details: [
      'User activity patterns',
      'Installed application risks',
      'Browser usage patterns',
      'System configuration anomalies',
      'Security software status'
    ],
    useCases: [
      'Insider threat detection',
      'User security awareness evaluation',
      'Behavioral security analysis',
      'Security culture assessment'
    ],
    complianceFrameworks: ['NIST CSF', 'SOC 2'],
    technicalDetails: {
      whatItChecks: [
        'User activity patterns and installed application risks',
        'Browser usage patterns and system configuration anomalies',
        'Security software status and behavioral indicators'
      ],
      howItChecks: [
        {
          section: 'User Activity',
          details: [
            'Analyzes recent user login patterns and activity',
            'Examines installed applications for security risks',
            'Checks for suspicious browser usage patterns'
          ]
        }
      ]
    }
  },
  // Network-Based Assessment Modules
  {
    name: 'Port & Service Discovery',
    checkType: 'PORT_SERVICE_DISCOVERY',
    description: 'Discovers open TCP and UDP ports on local network hosts with basic service identification and banner grabbing.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Network,
    details: [
      'Open TCP and UDP port discovery',
      'Service banner grabbing and identification',
      'Network service enumeration',
      'Port-based risk assessment',
      'Active host detection'
    ],
    useCases: [
      'Network security assessments',
      'Attack surface analysis',
      'Service inventory management',
      'Network asset discovery'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Common TCP ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900)',
        'UDP services (53, 69, 123, 161, 514)',
        'Service banners and version information',
        'HTTP/HTTPS service detection and headers',
        'Database service discovery (MySQL, PostgreSQL, MSSQL)'
      ],
      howItChecks: [
        {
          section: 'Host Discovery',
          details: [
            'Enumerates network interfaces and determines local subnets',
            'Generates target IP ranges within discovered subnets',
            'Limits scan to reasonable subnet sizes (/20 to /30)',
            'Uses concurrent scanning with configurable timeout'
          ]
        },
        {
          section: 'Port Scanning',
          details: [
            'TCP connect scans to common service ports',
            'UDP probes for DNS, SNMP, and other UDP services',
            'Configurable timeout (default 1000ms per connection)',
            'Concurrent scanning with rate limiting to avoid network congestion'
          ]
        },
        {
          section: 'Service Identification',
          details: [
            'Banner grabbing for SSH, FTP, SMTP, and other text protocols',
            'HTTP HEAD requests for web service identification',
            'Service-specific probes (MySQL handshake, SMB negotiation)',
            'Version string extraction and normalization'
          ]
        },
        {
          section: 'Risk Assessment',
          details: [
            'Assigns risk levels based on service type and configuration',
            'Flags unencrypted services (Telnet, FTP, HTTP)',
            'Identifies potentially vulnerable service versions',
            'Correlates services with known attack vectors'
          ]
        }
      ],
      limitations: [
        'Limited to predefined port list - may miss custom services',
        'Network timeouts may cause false negatives on slow networks',
        'Banner grabbing may not work with all service types',
        'Does not perform deep protocol analysis or vulnerability scanning'
      ],
      remediation: [
        'Close unnecessary ports and disable unused services',
        'Implement network segmentation to limit service exposure',
        'Use encrypted alternatives (SSH instead of Telnet, HTTPS instead of HTTP)',
        'Configure firewalls to restrict access to sensitive services',
        'Regularly update services to latest versions'
      ]
    }
  },
  {
    name: 'Operating System Fingerprinting',
    checkType: 'OS_FINGERPRINTING',
    description: 'Identifies remote host operating systems using passive and active fingerprinting techniques including TCP characteristics and service banners.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Monitor,
    details: [
      'TCP/IP stack fingerprinting',
      'Service banner analysis',
      'Operating system version detection',
      'Network behavior analysis',
      'Device type classification'
    ],
    useCases: [
      'Network asset inventory',
      'Security posture assessment',
      'Compliance verification',
      'Attack surface mapping'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'TCP window sizes, MSS, and other TCP options',
        'HTTP server headers and signature patterns',
        'SSH version strings and supported algorithms',
        'SMB protocol versions and dialects',
        'DNS response characteristics and behavior'
      ],
      howItChecks: [
        {
          section: 'TCP Fingerprinting',
          details: [
            'Analyzes TCP window scaling and MSS values',
            'Examines TCP options order and values',
            'Tests TCP timestamp behavior',
            'Evaluates ICMP responses and TTL values'
          ]
        },
        {
          section: 'Service Banner Analysis',
          details: [
            'Extracts version information from SSH banners',
            'Analyzes HTTP Server headers for OS indicators',
            'Examines SMB negotiation responses',
            'Correlates service versions with typical OS distributions'
          ]
        },
        {
          section: 'Behavioral Analysis',
          details: [
            'Tests response timing characteristics',
            'Analyzes error message formats',
            'Examines default service configurations',
            'Correlates multiple signals for confidence scoring'
          ]
        }
      ],
      limitations: [
        'Modern OS stacks are increasingly similar, reducing accuracy',
        'Firewalls and NAT can obscure fingerprinting signals',
        'Virtual machines may present hypervisor characteristics',
        'Limited effectiveness against hardened or customized systems'
      ],
      remediation: [
        'Configure services to minimize information disclosure',
        'Use generic or misleading banners where appropriate',
        'Implement network-level obfuscation techniques',
        'Deploy deception technologies to confuse attackers'
      ]
    }
  },
  {
    name: 'Shared Folder / SMB Discovery',
    checkType: 'SMB_SHARE_DISCOVERY',
    description: 'Enumerates SMB shares and detects anonymous access indicators on hosts that expose SMB-related ports without attempting file operations.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Share2,
    details: [
      'SMB share enumeration',
      'Anonymous access detection',
      'Share permission analysis',
      'NetBIOS name resolution',
      'SMB version identification'
    ],
    useCases: [
      'Data exposure assessments',
      'Network share security audits',
      'Compliance verification',
      'Lateral movement risk analysis'
    ],
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'SMB/CIFS service availability on ports 139 and 445',
        'Anonymous share enumeration capabilities',
        'Default administrative shares (C$, ADMIN$, IPC$)',
        'NetBIOS name resolution and workgroup information',
        'SMB protocol version and security features'
      ],
      howItChecks: [
        {
          section: 'SMB Service Detection',
          details: [
            'Scans for SMB services on TCP ports 139 (NetBIOS) and 445 (SMB)',
            'Attempts SMB protocol negotiation to determine version',
            'Identifies SMB1, SMB2, and SMB3 protocol support',
            'Detects signing requirements and encryption capabilities'
          ]
        },
        {
          section: 'Share Enumeration',
          details: [
            'Performs anonymous SMB session establishment',
            'Enumerates available shares using NetShareEnum API calls',
            'Identifies share types (disk, print, device, IPC)',
            'Attempts to list share contents without authentication'
          ]
        },
        {
          section: 'Access Control Analysis',
          details: [
            'Tests anonymous access to discovered shares',
            'Identifies readable and writable shares',
            'Checks for default credentials on administrative shares',
            'Evaluates share-level vs NTFS permissions'
          ]
        },
        {
          section: 'NetBIOS Information Gathering',
          details: [
            'Resolves NetBIOS names to identify computer names',
            'Enumerates domain/workgroup membership',
            'Collects system information through NetBIOS queries',
            'Identifies master browser and domain controller roles'
          ]
        }
      ],
      limitations: [
        'Modern Windows systems often restrict anonymous access by default',
        'Domain-joined computers may have different security policies',
        'Network segmentation can prevent cross-subnet discovery',
        'SMB signing and encryption may limit information gathering'
      ],
      remediation: [
        'Disable anonymous access to shares and IPC$',
        'Remove or restrict administrative shares where not needed',
        'Enable SMB signing and encryption',
        'Implement network segmentation to isolate file servers',
        'Use principle of least privilege for share permissions'
      ]
    }
  },
  {
    name: 'Default Web Page / Device Portal Check',
    checkType: 'WEB_PORTAL_DISCOVERY',
    description: 'Discovers web admin consoles, default web pages, and device portals that expose login pages or management interfaces without attempting authentication.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Globe,
    details: [
      'Web administration interface discovery',
      'Default installation page detection',
      'Device management portal identification',
      'Login page enumeration',
      'Technology stack fingerprinting'
    ],
    useCases: [
      'Web application security assessment',
      'IoT device discovery',
      'Administrative interface enumeration',
      'Default credential risk assessment'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'HTTP and HTTPS services on standard (80, 443) and non-standard ports',
        'Default installation pages (Apache, IIS, nginx welcome pages)',
        'Administrative interfaces (cPanel, phpMyAdmin, router config)',
        'Device management portals (printers, cameras, IoT devices)',
        'Framework and CMS detection (WordPress, Drupal, etc.)'
      ],
      howItChecks: [
        {
          section: 'Web Service Discovery',
          details: [
            'Scans for HTTP services on common and non-standard ports',
            'Performs HTTP HEAD and GET requests to root paths',
            'Follows redirects to identify actual landing pages',
            'Analyzes response headers for server and technology information'
          ]
        },
        {
          section: 'Default Page Detection',
          details: [
            'Matches response content against known default page signatures',
            'Identifies Apache "It Works!" pages and IIS default installations',
            'Detects nginx welcome pages and development frameworks',
            'Recognizes placeholder and "under construction" pages'
          ]
        },
        {
          section: 'Administrative Interface Identification',
          details: [
            'Tests common admin paths (/admin, /login, /config, /management)',
            'Identifies login forms and authentication mechanisms',
            'Detects web-based management interfaces',
            'Recognizes common admin frameworks and tools'
          ]
        },
        {
          section: 'Technology Fingerprinting',
          details: [
            'Analyzes HTTP headers for server and framework versions',
            'Examines HTML content for CMS and framework indicators',
            'Detects JavaScript frameworks and libraries',
            'Identifies database admin tools and development interfaces'
          ]
        }
      ],
      limitations: [
        'Limited to HTTP-based interfaces - does not detect non-web admin tools',
        'May miss custom or non-standard administrative interfaces',
        'Cannot determine actual security of detected interfaces',
        'False positives possible with legitimate development/staging sites'
      ],
      remediation: [
        'Remove or secure default installation pages',
        'Change default administrative paths and implement access controls',
        'Use strong authentication for all admin interfaces',
        'Implement network-level restrictions for management interfaces',
        'Regularly audit and inventory web-accessible administrative tools'
      ]
    }
  },
  {
    name: 'Basic Traffic Visibility Test',
    checkType: 'TRAFFIC_VISIBILITY',
    description: 'Tests for broadcast/multicast protocol responses that may leak hostname or service information.',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Radio,
    details: [
      'LLMNR (Link-Local Multicast Name Resolution) testing',
      'mDNS (Multicast DNS) service discovery',
      'NetBIOS broadcast enumeration',
      'Hostname information leakage',
      'Service advertisement analysis'
    ],
    useCases: [
      'Information disclosure assessment',
      'Network reconnaissance evaluation',
      'Privacy and anonymity testing',
      'Broadcast protocol security audit'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'LLMNR responses on UDP port 5355 (multicast 224.0.0.252)',
        'mDNS service advertisements on UDP port 5353 (multicast 224.0.0.251)',
        'NetBIOS name service broadcasts on UDP port 137',
        'Hostname resolution through broadcast protocols',
        'Service discovery information leakage'
      ],
      howItChecks: [
        {
          section: 'LLMNR Testing',
          details: [
            'Sends LLMNR queries for test hostnames to multicast address',
            'Listens for responses that reveal actual hostnames',
            'Analyzes response timing and source identification',
            'Evaluates information disclosure risk level'
          ]
        },
        {
          section: 'mDNS Service Discovery',
          details: [
            'Performs mDNS service enumeration queries',
            'Discovers advertised services and their details',
            'Identifies device types and service capabilities',
            'Analyzes service records for sensitive information'
          ]
        },
        {
          section: 'NetBIOS Name Service',
          details: [
            'Sends NetBIOS name queries and wildcards',
            'Collects hostname and workgroup information',
            'Tests for anonymous NetBIOS enumeration',
            'Evaluates network browsing capabilities'
          ]
        },
        {
          section: 'Information Leakage Analysis',
          details: [
            'Correlates responses across multiple protocols',
            'Identifies unique device and service fingerprints',
            'Evaluates privacy implications of broadcast responses',
            'Assesses potential for network mapping and reconnaissance'
          ]
        }
      ],
      limitations: [
        'Testing limited to local network segments',
        'May not detect all broadcast/multicast protocols',
        'Network configuration can affect protocol behavior',
        'Results depend on local network topology and policies'
      ],
      remediation: [
        'Disable LLMNR via Group Policy or registry settings',
        'Configure DNS properly to reduce LLMNR fallback usage',
        'Disable NetBIOS over TCP/IP where not required',
        'Implement network segmentation to limit broadcast domains',
        'Monitor and control multicast traffic at network boundaries'
      ]
    }
  },
  {
    name: 'RDP & Remote Access Exposure',
    checkType: 'REMOTE_ACCESS_EXPOSURE',
    description: 'Identifies exposed remote-access services (RDP, VNC, common VPN portals) and detects basic protection signals such as RDP NLA.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Monitor,
    details: [
      'RDP service exposure detection',
      'Network Level Authentication (NLA) verification',
      'VNC service identification',
      'VPN portal discovery',
      'Remote access security assessment'
    ],
    useCases: [
      'Remote access security audit',
      'Lateral movement risk assessment',
      'VPN and remote work security evaluation',
      'Attack surface reduction'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls', 'SOC 2'],
    technicalDetails: {
      whatItChecks: [
        'RDP services on port 3389 and Network Level Authentication status',
        'VNC services on port 5900 with protocol identification',
        'VPN portal detection on HTTPS with certificate analysis',
        'PPTP VPN service on port 1723 (deprecated protocol)',
        'Remote access service configurations and security features'
      ],
      howItChecks: [
        {
          section: 'RDP Security Assessment',
          details: [
            'Tests TCP connectivity to port 3389',
            'Attempts TLS handshake to detect NLA implementation',
            'Evaluates RDP certificate and encryption settings',
            'Identifies RDP version and security capabilities'
          ]
        },
        {
          section: 'VNC Service Detection',
          details: [
            'Connects to port 5900 and analyzes RFB protocol handshake',
            'Identifies VNC server version and capabilities',
            'Tests for authentication requirements',
            'Evaluates encryption and security features'
          ]
        },
        {
          section: 'VPN Portal Discovery',
          details: [
            'Analyzes HTTPS certificates for VPN vendor keywords',
            'Identifies common VPN portal signatures in HTTP responses',
            'Tests for vendor-specific VPN portal characteristics',
            'Evaluates SSL/TLS configuration security'
          ]
        },
        {
          section: 'Legacy Protocol Detection',
          details: [
            'Scans for deprecated PPTP VPN service on port 1723',
            'Identifies other legacy remote access protocols',
            'Tests for insecure remote access configurations',
            'Evaluates protocol security and encryption capabilities'
          ]
        }
      ],
      limitations: [
        'NLA detection uses heuristic TLS handshake testing',
        'May not detect all VPN portal types or custom implementations',
        'Cannot evaluate actual authentication security',
        'Limited to network-accessible services only'
      ],
      remediation: [
        'Enable Network Level Authentication for RDP',
        'Place remote access services behind VPN or gateway',
        'Implement multi-factor authentication for all remote access',
        'Disable deprecated protocols like PPTP',
        'Use secure alternatives and restrict access to management VLANs'
      ]
    }
  },
  {
    name: 'DNS Hygiene Check',
    checkType: 'DNS_HYGIENE_CHECK',
    description: 'Checks internal DNS servers for open recursion, zone transfer (AXFR) exposure, and internal record leakage.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Globe,
    details: [
      'DNS server security configuration',
      'Zone transfer vulnerability testing',
      'Open recursion detection',
      'Internal DNS record enumeration',
      'DNS security feature analysis'
    ],
    useCases: [
      'DNS security assessment',
      'Information disclosure prevention',
      'Network security configuration audit',
      'DNS infrastructure hardening'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'DNS servers allowing unauthorized zone transfers (AXFR)',
        'Open recursive DNS servers accessible from internal networks',
        'DNS server version information disclosure',
        'Internal domain and subdomain enumeration',
        'DNS security extensions (DNSSEC) implementation'
      ],
      howItChecks: [
        {
          section: 'Zone Transfer Testing',
          details: [
            'Identifies authoritative DNS servers for discovered domains',
            'Attempts AXFR (full zone transfer) requests',
            'Tests IXFR (incremental zone transfer) capabilities',
            'Analyzes transferred records for sensitive information'
          ]
        },
        {
          section: 'Open Recursion Detection',
          details: [
            'Tests DNS servers for recursive query acceptance',
            'Evaluates response to external domain queries',
            'Identifies DNS servers that can be used for amplification attacks',
            'Tests for DNS forwarding configurations'
          ]
        },
        {
          section: 'Information Disclosure',
          details: [
            'Queries for DNS server version information',
            'Enumerates common internal subdomains and services',
            'Tests for DNS wildcard configurations',
            'Analyzes DNS responses for infrastructure details'
          ]
        },
        {
          section: 'Security Configuration Analysis',
          details: [
            'Evaluates DNSSEC implementation and validation',
            'Tests for DNS over HTTPS (DoH) and DNS over TLS (DoT) support',
            'Analyzes DNS cache poisoning resistance',
            'Assesses DNS logging and monitoring capabilities'
          ]
        }
      ],
      limitations: [
        'Testing limited to accessible DNS servers',
        'May not detect all internal DNS infrastructure',
        'Zone transfer testing depends on network access permissions',
        'Cannot evaluate all DNS security policies'
      ],
      remediation: [
        'Restrict zone transfers to authorized secondary servers only',
        'Disable recursive queries for external clients',
        'Hide DNS server version information',
        'Implement DNS filtering and monitoring',
        'Enable DNSSEC where appropriate and keep software updated'
      ]
    }
  },
  {
    name: 'Printer / IoT Device Enumeration',
    checkType: 'PRINTER_ENUMERATION',
    description: 'Identifies unmanaged printers and IoT devices using SNMP (public), HTTP headers/pages, and common device ports (9100, 554, 5000, 80/443).',
    riskLevel: 'MEDIUM',
    requiresAdmin: false,
    icon: Printer,
    details: [
      'Network printer discovery',
      'IoT device identification',
      'SNMP community string testing',
      'Device management interface detection',
      'Firmware version identification'
    ],
    useCases: [
      'IoT security assessment',
      'Shadow IT device discovery',
      'Network asset inventory',
      'Device security posture evaluation'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls'],
    technicalDetails: {
      whatItChecks: [
        'Network printers on standard ports (9100 JetDirect, 515 LPD, 631 IPP)',
        'SNMP-enabled devices with default community strings',
        'HTTP/HTTPS management interfaces on ports 80, 443, 8080, 8443',
        'IoT device ports (554 RTSP, 5000 UPnP, 1900 SSDP)',
        'Device identification through banner grabbing and HTTP headers'
      ],
      howItChecks: [
        {
          section: 'Printer Service Detection',
          details: [
            'Scans for HP JetDirect service on port 9100',
            'Tests Line Printer Daemon (LPD) on port 515',
            'Identifies Internet Printing Protocol (IPP) on port 631',
            'Detects proprietary printer protocols and services'
          ]
        },
        {
          section: 'SNMP Device Discovery',
          details: [
            'Tests SNMP v1/v2c with default community strings (public, private)',
            'Queries system information OIDs for device identification',
            'Retrieves device model, firmware version, and network configuration',
            'Enumerates network interfaces and device capabilities'
          ]
        },
        {
          section: 'Web Interface Analysis',
          details: [
            'Identifies HTTP-based device management interfaces',
            'Analyzes HTTP headers for device vendor and model information',
            'Tests for default login pages and authentication mechanisms',
            'Detects embedded web servers and their security configurations'
          ]
        },
        {
          section: 'IoT Protocol Detection',
          details: [
            'Scans for RTSP video streams on port 554',
            'Identifies UPnP services and device advertisements',
            'Tests for insecure IoT protocols and services',
            'Analyzes device response patterns for fingerprinting'
          ]
        }
      ],
      limitations: [
        'Limited to known ports and protocols',
        'May not detect all IoT device types or custom implementations',
        'SNMP testing limited to common community strings',
        'Cannot evaluate actual device security posture'
      ],
      remediation: [
        'Change default SNMP community strings and disable if not needed',
        'Segment IoT devices into dedicated VLANs',
        'Update device firmware regularly and disable unnecessary services',
        'Implement device authentication and monitoring',
        'Use network access control to manage device connectivity'
      ]
    }
  },
  {
    name: 'Unpatched Service Banner Detection',
    checkType: 'UNPATCHED_BANNER_DETECTION',
    description: 'Grabs lightweight banners/headers and normalizes version strings (e.g., Apache 2.2.15, OpenSSH_7.2) to flag likely outdated or EOL software.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Search,
    details: [
      'Service version identification',
      'End-of-life software detection',
      'Vulnerability correlation',
      'Patch level assessment',
      'Software inventory compilation'
    ],
    useCases: [
      'Vulnerability management',
      'Patch compliance verification',
      'Software inventory auditing',
      'Security risk assessment'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls', 'SOC 2'],
    technicalDetails: {
      whatItChecks: [
        'HTTP server banners (Apache, nginx, IIS) with version information',
        'SSH service banners (OpenSSH, proprietary implementations)',
        'FTP, SMTP, and other protocol banners with version strings',
        'Database service version identification (MySQL, PostgreSQL)',
        'Common service ports for banner grabbing and version extraction'
      ],
      howItChecks: [
        {
          section: 'Service Banner Collection',
          details: [
            'Connects to common service ports (21, 22, 25, 80, 443, etc.)',
            'Performs protocol-specific handshakes to elicit version information',
            'Collects HTTP headers including Server and X-Powered-By',
            'Extracts version strings from initial service responses'
          ]
        },
        {
          section: 'Version String Normalization',
          details: [
            'Parses banner text using regex patterns for common software',
            'Extracts product names and version numbers',
            'Normalizes version formats across different software types',
            'Correlates versions with known release and EOL dates'
          ]
        },
        {
          section: 'Age Assessment',
          details: [
            'Compares detected versions against current releases',
            'Identifies end-of-life (EOL) software versions',
            'Flags versions with known critical vulnerabilities',
            'Assigns risk scores based on age and vulnerability exposure'
          ]
        },
        {
          section: 'Vulnerability Correlation',
          details: [
            'Maps detected versions to CVE databases',
            'Identifies software with active exploit availability',
            'Prioritizes findings based on CVSS scores and exploitability',
            'Provides remediation guidance for detected issues'
          ]
        }
      ],
      limitations: [
        'Limited to services that provide version information in banners',
        'May not detect custom or modified software versions',
        'Version detection accuracy depends on banner content',
        'Cannot determine actual patch level or security configuration'
      ],
      remediation: [
        'Update identified software to current supported versions',
        'Disable version disclosure in service banners where possible',
        'Implement vulnerability scanning and patch management programs',
        'Replace end-of-life software with supported alternatives',
        'Monitor for security advisories affecting detected software'
      ]
    }
  },
  {
    name: 'Weak Protocol Detection',
    checkType: 'WEAK_PROTOCOL_DETECTION',
    description: 'Detects legacy or unencrypted services (e.g., Telnet/FTP/LDAP), plaintext protocols, and outdated TLS versions accepted by services.',
    riskLevel: 'HIGH',
    requiresAdmin: false,
    icon: Wifi,
    details: [
      'Legacy protocol identification',
      'Unencrypted service detection',
      'TLS/SSL version assessment',
      'Cipher suite evaluation',
      'Protocol security analysis'
    ],
    useCases: [
      'Protocol security assessment',
      'Encryption compliance verification',
      'Legacy system identification',
      'Network security hardening'
    ],
    complianceFrameworks: ['NIST CSF', 'CIS Controls', 'SOC 2'],
    technicalDetails: {
      whatItChecks: [
        'Unencrypted protocols (Telnet port 23, FTP port 21, HTTP port 80)',
        'Legacy authentication protocols (LDAP without StartTLS)',
        'Outdated SSL/TLS versions (SSLv3, TLS 1.0, TLS 1.1)',
        'Weak cipher suites and key exchange methods',
        'Services supporting both encrypted and unencrypted connections'
      ],
      howItChecks: [
        {
          section: 'Legacy Protocol Detection',
          details: [
            'Scans for Telnet, FTP, and other unencrypted services',
            'Tests for clear-text authentication mechanisms',
            'Identifies services using deprecated protocols',
            'Evaluates protocol security features and capabilities'
          ]
        },
        {
          section: 'TLS/SSL Assessment',
          details: [
            'Tests SSL/TLS handshake with various protocol versions',
            'Identifies supported cipher suites and their strength',
            'Evaluates certificate validation and chain integrity',
            'Tests for SSL/TLS vulnerabilities (POODLE, BEAST, etc.)'
          ]
        },
        {
          section: 'Encryption Analysis',
          details: [
            'Assesses encryption strength and key lengths',
            'Identifies perfect forward secrecy support',
            'Evaluates certificate algorithms and signatures',
            'Tests for secure renegotiation and other security features'
          ]
        },
        {
          section: 'Protocol Migration Assessment',
          details: [
            'Identifies services offering both secure and insecure versions',
            'Tests for automatic upgrade capabilities (HTTP to HTTPS)',
            'Evaluates migration paths from legacy to secure protocols',
            'Assesses business impact of protocol deprecation'
          ]
        }
      ],
      limitations: [
        'Cannot test all possible protocol combinations',
        'May not detect custom or proprietary weak protocols',
        'Testing limited to network-accessible services',
        'Cannot evaluate actual data transmission security'
      ],
      remediation: [
        'Disable or replace insecure protocols with encrypted alternatives',
        'Enforce minimum TLS version requirements (TLS 1.2 or higher)',
        'Configure strong cipher suites and disable weak algorithms',
        'Implement protocol migration strategies for legacy systems',
        'Monitor and audit protocol usage across the network'
      ]
    }
  }
];

const environmentRecommendations = {
  'Cloud Environments': {
    modules: ['Data Exposure Check', 'Excessive Sharing & Collaboration Risks', 'Misconfiguration Discovery', 'Phishing Exposure Indicators', 'Weak Protocol Detection', 'DNS Hygiene Check'],
    rationale: 'Cloud environments require focus on data protection, sharing controls, configuration management, and secure network protocols.'
  },
  'Network Infrastructure': {
    modules: ['Port & Service Discovery', 'Operating System Fingerprinting', 'DNS Hygiene Check', 'Unpatched Service Banner Detection', 'Weak Protocol Detection', 'RDP & Remote Access Exposure', 'Misconfiguration Discovery'],
    rationale: 'Network infrastructure assessments prioritize attack surface reduction, service hardening, and comprehensive network security analysis.'
  },
  'On-Premises Infrastructure': {
    modules: ['Patch & Update Status', 'Weak Password Detection', 'Password Policy Weakness', 'Elevated Permissions Report', 'Misconfiguration Discovery', 'Shared Folder / SMB Discovery', 'Port & Service Discovery', 'Printer / IoT Device Enumeration'],
    rationale: 'On-premises environments benefit from comprehensive identity and system hardening assessments plus network-based discovery of internal assets and services.'
  },
  'End-User Workstations': {
    modules: ['Phishing Exposure Indicators', 'User Behavior Risk Signals', 'Patch & Update Status', 'Data Exposure Check', 'Basic Traffic Visibility Test'],
    rationale: 'Workstation assessments focus on user-related risks, endpoint protection, and information disclosure through network protocols.'
  },
  'IoT and Device Networks': {
    modules: ['Printer / IoT Device Enumeration', 'Default Web Page / Device Portal Check', 'Weak Protocol Detection', 'Port & Service Discovery', 'Basic Traffic Visibility Test'],
    rationale: 'IoT environments require specialized discovery techniques and security assessment of device management interfaces and protocols.'
  }
};

const complianceMapping = {
  'SOC 2 Type II': {
    modules: ['Misconfiguration Discovery', 'Weak Password Detection', 'Data Exposure Check', 'Elevated Permissions Report', 'Password Policy Weakness', 'RDP & Remote Access Exposure', 'Shared Folder / SMB Discovery', 'Weak Protocol Detection'],
    controls: ['CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7', 'CC6.8']
  },
  'NIST Cybersecurity Framework': {
    modules: ['Patch & Update Status', 'Misconfiguration Discovery', 'Data Exposure Check', 'Port & Service Discovery', 'Phishing Exposure Indicators', 'Operating System Fingerprinting', 'DNS Hygiene Check', 'Unpatched Service Banner Detection', 'Weak Protocol Detection'],
    controls: ['ID.RA', 'PR.IP', 'PR.DS', 'ID.AM', 'PR.AC', 'PR.AT', 'DE.CM', 'ID.RA-1', 'ID.AM-1', 'ID.AM-2']
  },
  'CIS Controls v8': {
    modules: ['Patch & Update Status', 'Elevated Permissions Report', 'Misconfiguration Discovery', 'Data Exposure Check', 'Password Policy Weakness', 'Port & Service Discovery', 'Operating System Fingerprinting', 'Printer / IoT Device Enumeration', 'Weak Protocol Detection'],
    controls: ['Control 1', 'Control 2', 'Control 3', 'Control 4', 'Control 6', 'Control 7', 'Control 11', 'Control 12']
  },
  'GDPR/CCPA Data Protection': {
    modules: ['Data Exposure Check', 'Excessive Sharing & Collaboration Risks', 'Elevated Permissions Report', 'Misconfiguration Discovery', 'Shared Folder / SMB Discovery', 'Basic Traffic Visibility Test'],
    controls: ['Article 25', 'Article 32', 'CCPA 1798.100', 'CCPA 1798.150']
  },
  'ISO 27001:2022': {
    modules: ['Port & Service Discovery', 'Operating System Fingerprinting', 'DNS Hygiene Check', 'Unpatched Service Banner Detection', 'RDP & Remote Access Exposure', 'Weak Protocol Detection', 'Misconfiguration Discovery', 'Data Exposure Check'],
    controls: ['A.8.9', 'A.8.10', 'A.12.6', 'A.13.1', 'A.14.1', 'A.18.1']
  }
};

const testingFrequency = {
  'Critical Risk (Weekly)': ['Patch & Update Status', 'Weak Password Detection', 'Data Exposure Check', 'RDP & Remote Access Exposure', 'DNS Hygiene Check', 'Unpatched Service Banner Detection'],
  'High Risk (Bi-weekly)': ['Misconfiguration Discovery', 'Elevated Permissions Report', 'Password Policy Weakness', 'Phishing Exposure Indicators', 'Shared Folder / SMB Discovery', 'Weak Protocol Detection'],
  'Medium Risk (Monthly)': ['Port & Service Discovery', 'Excessive Sharing & Collaboration Risks', 'User Behavior Risk Signals', 'Operating System Fingerprinting', 'Default Web Page / Device Portal Check', 'Printer / IoT Device Enumeration', 'Basic Traffic Visibility Test']
};

export default function DocumentationPage() {
  const [activeTab, setActiveTab] = useState<'modules' | 'technical' | 'environments' | 'compliance' | 'frequency'>('modules');
  const [selectedModule, setSelectedModule] = useState<ModuleInfo | null>(null);

  const getRiskLevelColor = (level: string) => {
    switch (level) {
      case 'HIGH': return 'text-red-600 bg-red-50';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-50';
      case 'LOW': return 'text-green-600 bg-green-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getRiskLevelIcon = (level: string) => {
    switch (level) {
      case 'HIGH': return AlertTriangle;
      case 'MEDIUM': return Clock;
      case 'LOW': return CheckCircle;
      default: return Info;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Security Assessment Documentation</h1>
        <p className="mt-2 text-gray-600">
          Comprehensive documentation for all available security modules, compliance mapping, and testing recommendations.
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          {[
            { id: 'modules', name: 'Modules', icon: Shield },
            { id: 'technical', name: 'Technical Details', icon: Code },
            { id: 'environments', name: 'Environments', icon: Network },
            { id: 'compliance', name: 'Compliance', icon: CheckCircle },
            { id: 'frequency', name: 'Testing Schedule', icon: Clock },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center px-1 py-4 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Content */}
      {activeTab === 'modules' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Module List */}
          <div className="lg:col-span-1 space-y-4">
            <h2 className="text-lg font-semibold text-gray-900">Available Modules</h2>
            <div className="space-y-3">
              {modules.map((module) => {
                const Icon = module.icon;
                const RiskIcon = getRiskLevelIcon(module.riskLevel);
                return (
                  <Card
                    key={module.checkType}
                    className={`p-4 cursor-pointer transition-colors ${
                      selectedModule?.checkType === module.checkType
                        ? 'bg-blue-50 border-blue-200'
                        : 'hover:bg-gray-50'
                    }`}
                    onClick={() => setSelectedModule(module)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <Icon className="h-5 w-5 text-blue-600 mt-0.5" />
                        <div className="flex-1">
                          <h3 className="text-sm font-medium text-gray-900">{module.name}</h3>
                          <div className="flex items-center mt-2 space-x-2">
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRiskLevelColor(module.riskLevel)}`}>
                              <RiskIcon className="h-3 w-3 mr-1" />
                              {module.riskLevel}
                            </span>
                            {module.requiresAdmin && (
                              <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium text-purple-600 bg-purple-50">
                                Admin Required
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <ChevronRight className="h-4 w-4 text-gray-400" />
                    </div>
                  </Card>
                );
              })}
            </div>
          </div>

          {/* Module Details */}
          <div className="lg:col-span-2">
            {selectedModule ? (
              <Card className="p-6">
                <div className="flex items-start space-x-4">
                  <selectedModule.icon className="h-8 w-8 text-blue-600 mt-1" />
                  <div className="flex-1">
                    <h2 className="text-xl font-semibold text-gray-900">{selectedModule.name}</h2>
                    <p className="mt-2 text-gray-600">{selectedModule.description}</p>

                    <div className="mt-4 flex items-center space-x-4">
                      <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${getRiskLevelColor(selectedModule.riskLevel)}`}>
                        {(() => {
                          const RiskIcon = getRiskLevelIcon(selectedModule.riskLevel);
                          return <RiskIcon className="h-4 w-4 mr-1" />;
                        })()}
                        {selectedModule.riskLevel} Risk
                      </span>
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium text-gray-600 bg-gray-100">
                        {selectedModule.requiresAdmin ? 'Admin Required' : 'Standard User'}
                      </span>
                    </div>

                    <div className="mt-6 space-y-6">
                      <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-3">What it checks:</h3>
                        <ul className="space-y-2">
                          {selectedModule.details.map((detail, index) => (
                            <li key={index} className="flex items-start">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" />
                              <span className="text-gray-600">{detail}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-3">Use Cases:</h3>
                        <ul className="space-y-2">
                          {selectedModule.useCases.map((useCase, index) => (
                            <li key={index} className="flex items-start">
                              <div className="h-2 w-2 bg-blue-600 rounded-full mt-2 mr-3 flex-shrink-0" />
                              <span className="text-gray-600">{useCase}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-3">Compliance Frameworks:</h3>
                        <div className="flex flex-wrap gap-2">
                          {selectedModule.complianceFrameworks.map((framework) => (
                            <span key={framework} className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium text-blue-600 bg-blue-50">
                              {framework}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </Card>
            ) : (
              <Card className="p-8 text-center">
                <Shield className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Module</h3>
                <p className="text-gray-600">Choose a module from the list to view detailed information about its capabilities and use cases.</p>
              </Card>
            )}
          </div>
        </div>
      )}

      {activeTab === 'technical' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Module List */}
          <div className="lg:col-span-1 space-y-4">
            <h2 className="text-lg font-semibold text-gray-900">Technical Implementation</h2>
            <p className="text-sm text-gray-600 mb-4">
              Detailed technical information about module implementation and methodology. This shows the actual checks performed and registry keys examined.
            </p>
            <div className="space-y-3">
              {modules.filter(module => module.technicalDetails).map((module) => {
                const Icon = module.icon;
                const RiskIcon = getRiskLevelIcon(module.riskLevel);
                return (
                  <Card
                    key={module.checkType}
                    className={`p-4 cursor-pointer transition-colors ${
                      selectedModule?.checkType === module.checkType
                        ? 'bg-blue-50 border-blue-200'
                        : 'hover:bg-gray-50'
                    }`}
                    onClick={() => setSelectedModule(module)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <Icon className="h-5 w-5 text-blue-600 mt-0.5" />
                        <div className="flex-1">
                          <h3 className="text-sm font-medium text-gray-900">{module.name}</h3>
                          <div className="flex items-center mt-2 space-x-2">
                            <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getRiskLevelColor(module.riskLevel)}`}>
                              <RiskIcon className="h-3 w-3 mr-1" />
                              {module.riskLevel}
                            </span>
                            <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium text-gray-600 bg-gray-100">
                              <Settings className="h-3 w-3 mr-1" />
                              Technical
                            </span>
                          </div>
                        </div>
                      </div>
                      <ChevronRight className="h-4 w-4 text-gray-400" />
                    </div>
                  </Card>
                );
              })}
            </div>
          </div>

          {/* Technical Details */}
          <div className="lg:col-span-2">
            {selectedModule?.technicalDetails ? (
              <Card className="p-6">
                <div className="flex items-start space-x-4">
                  <selectedModule.icon className="h-8 w-8 text-blue-600 mt-1" />
                  <div className="flex-1">
                    <h2 className="text-xl font-semibold text-gray-900">{selectedModule.name}</h2>
                    <p className="mt-2 text-gray-600">Technical implementation details and methodology</p>

                    <div className="mt-6 space-y-8">
                      {/* What it checks */}
                      <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                          <Eye className="h-5 w-5 text-blue-600 mr-2" />
                          What it checks
                        </h3>
                        <ul className="space-y-2">
                          {selectedModule.technicalDetails.whatItChecks.map((item, index) => (
                            <li key={index} className="flex items-start">
                              <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" />
                              <span className="text-gray-600">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* How it checks */}
                      <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                          <Code className="h-5 w-5 text-blue-600 mr-2" />
                          How it checks
                        </h3>
                        <div className="space-y-6">
                          {selectedModule.technicalDetails.howItChecks.map((section, index) => (
                            <div key={index} className="border-l-4 border-blue-200 pl-4">
                              <h4 className="font-medium text-gray-900 mb-2">{section.section}</h4>
                              <ul className="space-y-1">
                                {section.details.map((detail, detailIndex) => (
                                  <li key={detailIndex} className="flex items-start">
                                    <div className="h-2 w-2 bg-blue-600 rounded-full mt-2 mr-3 flex-shrink-0" />
                                    <span className="text-sm text-gray-600">{detail}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Limitations */}
                      {selectedModule.technicalDetails.limitations && (
                        <div>
                          <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                            <AlertTriangle className="h-5 w-5 text-yellow-600 mr-2" />
                            Limitations & Edge Cases
                          </h3>
                          <ul className="space-y-2">
                            {selectedModule.technicalDetails.limitations.map((item, index) => (
                              <li key={index} className="flex items-start">
                                <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 mr-2 flex-shrink-0" />
                                <span className="text-gray-600">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Remediation */}
                      {selectedModule.technicalDetails.remediation && (
                        <div>
                          <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
                            <Shield className="h-5 w-5 text-green-600 mr-2" />
                            Recommended Remediations
                          </h3>
                          <ul className="space-y-2">
                            {selectedModule.technicalDetails.remediation.map((item, index) => (
                              <li key={index} className="flex items-start">
                                <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" />
                                <span className="text-gray-600">{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </Card>
            ) : (
              <Card className="p-8 text-center">
                <Code className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Module</h3>
                <p className="text-gray-600">Choose a module from the list to view detailed technical implementation information.</p>
              </Card>
            )}
          </div>
        </div>
      )}

      {activeTab === 'environments' && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold text-gray-900">Environment-Specific Recommendations</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {Object.entries(environmentRecommendations).map(([env, data]) => (
              <Card key={env} className="p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-3">{env}</h3>
                <p className="text-gray-600 mb-4">{data.rationale}</p>
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-2">Recommended Modules:</h4>
                  <ul className="space-y-2">
                    {data.modules.map((module) => (
                      <li key={module} className="flex items-center">
                        <CheckCircle className="h-4 w-4 text-green-500 mr-2" />
                        <span className="text-sm text-gray-600">{module}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold text-gray-900">Compliance Framework Mapping</h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {Object.entries(complianceMapping).map(([framework, data]) => (
              <Card key={framework} className="p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-3">{framework}</h3>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Required Modules:</h4>
                    <ul className="space-y-1">
                      {data.modules.map((module) => (
                        <li key={module} className="flex items-center">
                          <Shield className="h-3 w-3 text-blue-500 mr-2" />
                          <span className="text-sm text-gray-600">{module}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Relevant Controls:</h4>
                    <div className="flex flex-wrap gap-1">
                      {data.controls.map((control) => (
                        <span key={control} className="inline-flex items-center px-2 py-1 rounded text-xs font-medium text-blue-600 bg-blue-50">
                          {control}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'frequency' && (
        <div className="space-y-6">
          <h2 className="text-lg font-semibold text-gray-900">Testing Frequency Recommendations</h2>
          <div className="space-y-6">
            {Object.entries(testingFrequency).map(([frequency, moduleList]) => (
              <Card key={frequency} className="p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-3">{frequency}</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {moduleList.map((module) => (
                    <div key={module} className="flex items-center p-3 bg-gray-50 rounded-lg">
                      <Clock className="h-4 w-4 text-gray-500 mr-2" />
                      <span className="text-sm text-gray-700">{module}</span>
                    </div>
                  ))}
                </div>
              </Card>
            ))}

            <Card className="p-6 bg-blue-50 border-blue-200">
              <h3 className="text-lg font-medium text-blue-900 mb-3">Additional Recommendations</h3>
              <ul className="space-y-2 text-blue-800">
                <li className="flex items-start">
                  <CheckCircle className="h-4 w-4 text-blue-600 mt-0.5 mr-2 flex-shrink-0" />
                  <span><strong>Quarterly:</strong> Full comprehensive assessment (all modules)</span>
                </li>
                <li className="flex items-start">
                  <CheckCircle className="h-4 w-4 text-blue-600 mt-0.5 mr-2 flex-shrink-0" />
                  <span><strong>Annually:</strong> Complete compliance audit with all modules</span>
                </li>
                <li className="flex items-start">
                  <CheckCircle className="h-4 w-4 text-blue-600 mt-0.5 mr-2 flex-shrink-0" />
                  <span><strong>Ad-hoc:</strong> After major system changes or security incidents</span>
                </li>
              </ul>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}