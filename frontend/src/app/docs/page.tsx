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
  Info
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
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls']
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
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls']
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
    complianceFrameworks: ['GDPR', 'CCPA', 'SOC 2', 'NIST CSF']
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
    complianceFrameworks: ['NIST CSF', 'CIS Controls']
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
    complianceFrameworks: ['SOC 2', 'NIST CSF', 'CIS Controls']
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
    complianceFrameworks: ['GDPR', 'CCPA', 'SOC 2']
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
    complianceFrameworks: ['NIST CSF', 'CIS Controls']
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
    complianceFrameworks: ['NIST CSF', 'SOC 2']
  }
];

const environmentRecommendations = {
  'Cloud Environments': {
    modules: ['Data Exposure Check', 'Excessive Sharing & Collaboration Risks', 'Misconfiguration Discovery', 'Phishing Exposure Indicators'],
    rationale: 'Cloud environments require focus on data protection, sharing controls, and configuration management.'
  },
  'Network Infrastructure': {
    modules: ['Open Service/Port Identification', 'Misconfiguration Discovery', 'Patch & Update Status', 'Elevated Permissions Report'],
    rationale: 'Network infrastructure assessments prioritize attack surface reduction and privilege management.'
  },
  'On-Premises Infrastructure': {
    modules: ['Patch & Update Status', 'Weak Password Detection', 'Password Policy Weakness', 'Elevated Permissions Report', 'Misconfiguration Discovery'],
    rationale: 'On-premises environments benefit from comprehensive identity and system hardening assessments.'
  },
  'End-User Workstations': {
    modules: ['Phishing Exposure Indicators', 'User Behavior Risk Signals', 'Patch & Update Status', 'Data Exposure Check'],
    rationale: 'Workstation assessments focus on user-related risks and endpoint protection.'
  }
};

const complianceMapping = {
  'SOC 2 Type II': {
    modules: ['Misconfiguration Discovery', 'Weak Password Detection', 'Data Exposure Check', 'Elevated Permissions Report', 'Password Policy Weakness'],
    controls: ['CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7']
  },
  'NIST Cybersecurity Framework': {
    modules: ['Patch & Update Status', 'Misconfiguration Discovery', 'Data Exposure Check', 'Open Service/Port Identification', 'Phishing Exposure Indicators'],
    controls: ['ID.RA', 'PR.IP', 'PR.DS', 'ID.AM', 'PR.AC', 'PR.AT', 'DE.CM']
  },
  'CIS Controls v8': {
    modules: ['Patch & Update Status', 'Elevated Permissions Report', 'Misconfiguration Discovery', 'Data Exposure Check', 'Password Policy Weakness'],
    controls: ['Control 3', 'Control 4', 'Control 6', 'Control 7']
  },
  'GDPR/CCPA Data Protection': {
    modules: ['Data Exposure Check', 'Excessive Sharing & Collaboration Risks', 'Elevated Permissions Report', 'Misconfiguration Discovery'],
    controls: ['Article 25', 'Article 32', 'CCPA 1798.100']
  }
};

const testingFrequency = {
  'Critical Risk (Weekly)': ['Patch & Update Status', 'Weak Password Detection', 'Data Exposure Check'],
  'High Risk (Bi-weekly)': ['Misconfiguration Discovery', 'Elevated Permissions Report', 'Password Policy Weakness', 'Phishing Exposure Indicators'],
  'Medium Risk (Monthly)': ['Open Service/Port Identification', 'Excessive Sharing & Collaboration Risks', 'User Behavior Risk Signals']
};

export default function DocumentationPage() {
  const [activeTab, setActiveTab] = useState<'modules' | 'environments' | 'compliance' | 'frequency'>('modules');
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