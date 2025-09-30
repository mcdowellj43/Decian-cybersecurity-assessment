'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAssessments } from '@/hooks/useAssessments';
import { useAgents } from '@/hooks/useAgents';
import { reportApi } from '@/services/reportApi';
import { CheckType } from '@/services/assessmentApi';
import { agentApi, AgentModule } from '@/services/agentApi';
import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Play,
  FileText,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Filter,
  Download,
  MoreVertical,
  Loader2,
  Server,
  X,
  Trash2
} from 'lucide-react';

function LoadingSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      {[1, 2, 3].map((i) => (
        <Card key={i}>
          <CardContent className="p-6">
            <div className="space-y-4">
              <div className="flex justify-between items-start">
                <div className="space-y-2">
                  <div className="h-4 bg-gray-200 rounded w-32"></div>
                  <div className="h-6 bg-gray-200 rounded w-48"></div>
                </div>
                <div className="h-8 bg-gray-200 rounded w-20"></div>
              </div>
              <div className="h-4 bg-gray-200 rounded w-full"></div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ErrorState({ error }: { error: string }) {
  return (
    <Card className="border-red-200 bg-red-50">
      <CardContent className="p-6">
        <div className="flex items-center space-x-2">
          <AlertTriangle className="h-5 w-5 text-red-600" />
          <p className="text-red-800">Failed to load assessments: {error}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function AssessmentCard({ assessment, onDelete }: { assessment: any; onDelete: (id: string) => void }) {
  const router = useRouter();
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDropdown(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleViewDetails = () => {
    router.push('/reports');
  };

  const handleDelete = async () => {
    if (window.confirm(`Are you sure you want to delete assessment #${assessment.id.substring(0, 8)}? This action cannot be undone.`)) {
      await onDelete(assessment.id);
      setShowDropdown(false);
    }
  };

  const handleDownloadReport = async () => {
    try {
      // First try to get existing reports for this assessment
      const reportsResponse = await reportApi.getReports({ assessmentId: assessment.id });

      let reportId: string;

      if (reportsResponse.reports.length > 0) {
        // Use the most recent report
        reportId = reportsResponse.reports[0].id;
      } else {
        // Generate a new report
        const newReport = await reportApi.generate({
          assessmentId: assessment.id,
          title: `Security Assessment Report - ${new Date().toLocaleDateString()}`,
          includeDetails: true,
          includeExecutiveSummary: true
        });
        reportId = newReport.id;
      }

      // Download the report HTML
      const htmlContent = await reportApi.downloadHTML(reportId);

      // Create blob and download
      const blob = new Blob([htmlContent], { type: 'text/html' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `assessment-report-${assessment.id.substring(0, 8)}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download report:', error);
      alert('Failed to download report. Please try again.');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircle className="h-5 w-5 text-green-600" />;
      case 'RUNNING':
        return <Loader2 className="h-5 w-5 text-blue-600 animate-spin" />;
      case 'FAILED':
        return <XCircle className="h-5 w-5 text-red-600" />;
      case 'PENDING':
        return <Clock className="h-5 w-5 text-yellow-600" />;
      default:
        return <Clock className="h-5 w-5 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'RUNNING':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'FAILED':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'PENDING':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-6">
        <div className="space-y-4">
          <div className="flex justify-between items-start">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <Shield className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">
                  Assessment #{assessment.id.substring(0, 8)}
                </h3>
              </div>
              <p className="text-sm text-gray-600">
                Agent: {assessment.agent?.hostname || 'Unknown'}
              </p>
            </div>
            <div className={`flex items-center space-x-1 px-2 py-1 rounded-full border ${getStatusColor(assessment.status)}`}>
              {getStatusIcon(assessment.status)}
              <span className="text-xs font-medium">{assessment.status}</span>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Risk Score:</span>
              {assessment.overallRiskScore !== null ? (
                <RiskIndicator score={assessment.overallRiskScore} size="sm" />
              ) : (
                <span className="text-sm text-gray-400">Pending</span>
              )}
            </div>

            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Created:</span>
              <span className="text-gray-900">
                {new Date(assessment.createdAt).toLocaleDateString()}
              </span>
            </div>

            {assessment.completedAt && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Completed:</span>
                <span className="text-gray-900">
                  {new Date(assessment.completedAt).toLocaleDateString()}
                </span>
              </div>
            )}
          </div>

          <div className="flex space-x-2 pt-2">
            <Button variant="outline" size="sm" className="flex-1" onClick={handleViewDetails}>
              <FileText className="h-4 w-4 mr-1" />
              View Details
            </Button>
            {assessment.status === 'COMPLETED' && (
              <Button variant="ghost" size="sm" onClick={handleDownloadReport}>
                <Download className="h-4 w-4" />
              </Button>
            )}
            <div className="relative" ref={dropdownRef}>
              <Button variant="ghost" size="sm" onClick={() => setShowDropdown(!showDropdown)}>
                <MoreVertical className="h-4 w-4" />
              </Button>
              {showDropdown && (
                <div className="absolute right-0 mt-1 w-48 bg-white rounded-md shadow-lg border border-gray-200 z-10">
                  <div className="py-1">
                    <button
                      onClick={handleDelete}
                      className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete Assessment
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState({ onRunAssessment }: { onRunAssessment: () => void }) {
  return (
    <Card className="border-dashed border-2 border-gray-300">
      <CardContent className="p-12">
        <div className="text-center space-y-4">
          <Shield className="h-16 w-16 text-gray-400 mx-auto" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">No Assessments Yet</h3>
            <p className="text-gray-600 max-w-md mx-auto">
              Start your first security assessment to identify vulnerabilities and risks.
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="primary" onClick={onRunAssessment}>
              <Play className="h-4 w-4 mr-2" />
              Run Assessment
            </Button>
            <Button variant="outline">View Documentation</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CreateAssessmentModal({
  isOpen,
  onClose,
  agents,
  onCreateAssessment
}: {
  isOpen: boolean;
  onClose: () => void;
  agents: any[];
  onCreateAssessment: (agentId: string, scanType: 'host' | 'subnet', subnet?: string, selectedModules?: string[]) => void;
}) {
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [isCreating, setIsCreating] = useState(false);
  const [scanType, setScanType] = useState<'host' | 'subnet'>('host');
  const [subnet, setSubnet] = useState<string>('');
  const [availableModules, setAvailableModules] = useState<AgentModule[]>([]);
  const [selectedModules, setSelectedModules] = useState<string[]>([]);
  const [loadingModules, setLoadingModules] = useState(false);

  // Fetch modules when agent is selected
  useEffect(() => {
    const fetchModules = async () => {
      if (!selectedAgentId) {
        setAvailableModules([]);
        setSelectedModules([]);
        return;
      }

      setLoadingModules(true);
      try {
        const result = await agentApi.getAgentModules(selectedAgentId);
        console.log('Agent modules result:', result); // Debug logging

        // Defensive check for result and modules
        if (result && result.modules && Array.isArray(result.modules)) {
          setAvailableModules(result.modules);
          // Pre-select all modules by default
          setSelectedModules(result.modules.map(module => module.checkType));
        } else {
          console.warn('Invalid modules result structure:', result);
          setAvailableModules([]);
          setSelectedModules([]);
        }
      } catch (error) {
        console.error('Failed to fetch agent modules:', error);
        setAvailableModules([]);
        setSelectedModules([]);
      } finally {
        setLoadingModules(false);
      }
    };

    fetchModules();
  }, [selectedAgentId]);

  if (!isOpen) return null;

  // CIDR validation function
  const isValidCIDR = (cidr: string): boolean => {
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    return cidrRegex.test(cidr);
  };

  // Module selection handlers
  const handleModuleToggle = (moduleCheckType: string) => {
    setSelectedModules(prev =>
      prev.includes(moduleCheckType)
        ? prev.filter(m => m !== moduleCheckType)
        : [...prev, moduleCheckType]
    );
  };

  const handleSelectAllModules = () => {
    setSelectedModules(availableModules.map(module => module.checkType));
  };

  const handleDeselectAllModules = () => {
    setSelectedModules([]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgentId) return;

    // Validate subnet if subnet scan is selected
    if (scanType === 'subnet') {
      if (!subnet.trim()) {
        alert('Please enter a subnet CIDR (e.g., 192.168.1.0/24)');
        return;
      }
      if (!isValidCIDR(subnet.trim())) {
        alert('Please enter a valid CIDR format (e.g., 192.168.1.0/24)');
        return;
      }
    }

    // Validate module selection
    if (selectedModules.length === 0) {
      alert('Please select at least one assessment module');
      return;
    }

    setIsCreating(true);
    try {
      await onCreateAssessment(
        selectedAgentId,
        scanType,
        scanType === 'subnet' ? subnet.trim() : undefined,
        selectedModules
      );
      onClose();
      setSelectedAgentId('');
      setScanType('host');
      setSubnet('');
      setAvailableModules([]);
      setSelectedModules([]);
    } catch (error) {
      console.error('Failed to create assessment:', error);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-6 z-50">
      <div className="bg-white rounded-lg max-w-7xl w-full max-h-[90vh] overflow-hidden">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-900">Run Security Assessment</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="flex h-[calc(90vh-140px)]">
          {/* Left Column - Agent and Scan Options */}
          <div className="w-1/2 p-6 border-r border-gray-200 flex flex-col space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Select Agent
              </label>
              {agents.length === 0 ? (
                <div className="text-center py-8">
                  <Server className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                  <p className="text-gray-600 text-sm">No agents available</p>
                  <p className="text-gray-500 text-xs">Deploy an agent first to run assessments</p>
                </div>
              ) : (
                <select
                  value={selectedAgentId}
                  onChange={(e) => setSelectedAgentId(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  required
                >
                  <option value="">Choose an agent...</option>
                  {agents.map((agent) => (
                    <option key={agent.id} value={agent.id}>
                      {agent.hostname} ({agent.status})
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Scan Type
              </label>
              <div className="space-y-3">
                <label className="flex items-start space-x-3 p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors">
                  <input
                    type="radio"
                    name="scanType"
                    value="host"
                    checked={scanType === 'host'}
                    onChange={(e) => setScanType(e.target.value as 'host' | 'subnet')}
                    className="mt-1"
                  />
                  <div>
                    <div className="text-sm font-medium text-gray-900">Single Device Scan</div>
                    <div className="text-xs text-gray-600">
                      Scan only the device where the agent is running
                    </div>
                  </div>
                </label>
                <label className="flex items-start space-x-3 p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors">
                  <input
                    type="radio"
                    name="scanType"
                    value="subnet"
                    checked={scanType === 'subnet'}
                    onChange={(e) => setScanType(e.target.value as 'host' | 'subnet')}
                    className="mt-1"
                  />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900">Subnet Scan</div>
                    <div className="text-xs text-gray-600 mb-2">
                      Scan multiple devices across a network subnet
                    </div>
                    {scanType === 'subnet' && (
                      <div>
                        <input
                          type="text"
                          value={subnet}
                          onChange={(e) => setSubnet(e.target.value)}
                          placeholder="e.g., 192.168.1.0/24"
                          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                          required={scanType === 'subnet'}
                        />
                        <p className="text-xs text-gray-500 mt-1">
                          Enter CIDR notation (up to /24 supported)
                        </p>
                      </div>
                    )}
                  </div>
                </label>
              </div>
            </div>

            {/* Module Legend */}
            <div className="p-3 bg-gray-50 border border-gray-200 rounded-md">
              <h4 className="text-sm font-medium text-gray-900 mb-2">Module Types</h4>
              <div className="text-xs text-gray-700 space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="inline-block w-3 h-3 bg-blue-100 border border-blue-300 rounded"></span>
                  <span><strong>Host-Based:</strong> More intrusive, runs on the device</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="inline-block w-3 h-3 bg-purple-100 border border-purple-300 rounded"></span>
                  <span><strong>Network-Based:</strong> Less intrusive, scans over network</span>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex space-x-3 mt-auto pt-4">
              <Button type="button" variant="outline" onClick={onClose} className="flex-1">
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                className="flex-1"
                disabled={!selectedAgentId || isCreating || agents.length === 0 || selectedModules.length === 0}
              >
                {isCreating ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 mr-2" />
                    Run Assessment
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* Right Column - Module Selection */}
          <div className="w-1/2 flex flex-col">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h4 className="font-medium text-gray-900">Assessment Modules</h4>
                {availableModules.length > 0 && (
                  <div className="flex space-x-2">
                    <button
                      type="button"
                      onClick={handleSelectAllModules}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      Select All
                    </button>
                    <button
                      type="button"
                      onClick={handleDeselectAllModules}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      Clear All
                    </button>
                  </div>
                )}
              </div>
              {selectedModules.length > 0 && (
                <p className="text-xs text-gray-600 mt-1">
                  Selected: {selectedModules.length} of {availableModules.length} modules
                </p>
              )}
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              {!selectedAgentId ? (
                <div className="text-center py-12">
                  <Server className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                  <p className="text-sm text-gray-600">Select an agent to view available modules</p>
                </div>
              ) : loadingModules ? (
                <div className="flex items-center justify-center py-12">
                  <Loader2 className="h-5 w-5 animate-spin text-blue-600" />
                  <span className="ml-2 text-sm text-gray-600">Loading modules...</span>
                </div>
              ) : availableModules.length > 0 ? (
                <div className="space-y-3">
                  {availableModules.map((module) => (
                    <label key={module.checkType} className="flex items-start space-x-3 p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50 transition-colors">
                      <input
                        type="checkbox"
                        checked={selectedModules.includes(module.checkType)}
                        onChange={() => handleModuleToggle(module.checkType)}
                        className="mt-1 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-gray-900">{module.name}</div>
                        <div className="text-xs text-gray-600 mt-1">{module.description}</div>
                        <div className="flex items-center space-x-2 mt-2">
                          <span className={`text-xs px-2 py-1 rounded ${
                            module.category === 'host-based' ? 'bg-blue-100 text-blue-800' :
                            module.category === 'network-based' ? 'bg-purple-100 text-purple-800' :
                            'bg-gray-100 text-gray-800'
                          }`}>
                            {module.category === 'host-based' ? 'Host-Based' :
                             module.category === 'network-based' ? 'Network-Based' :
                             'Unknown'}
                          </span>
                          <span className={`text-xs px-2 py-1 rounded ${
                            module.defaultRiskLevel === 'HIGH' ? 'bg-red-100 text-red-800' :
                            module.defaultRiskLevel === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {module.defaultRiskLevel}
                          </span>
                          {module.requiresAdmin && (
                            <span className="text-xs text-orange-600 font-medium">Admin Required</span>
                          )}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12">
                  <p className="text-sm text-gray-600">No modules available</p>
                  <p className="text-xs text-gray-500">This agent may not be properly configured</p>
                </div>
              )}
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function AssessmentsPage() {
  const { assessments, isLoading, error, createAssessment, deleteAssessment } = useAssessments();
  const { agents } = useAgents();
  const [showCreateModal, setShowCreateModal] = useState(false);

  const handleRunAssessment = () => {
    setShowCreateModal(true);
  };

  const handleCreateAssessment = async (agentId: string, scanType: 'host' | 'subnet', subnet?: string, selectedModules?: string[]) => {
    try {
      const assessmentData = {
        agentId,
        modules: (selectedModules || []) as CheckType[],
        metadata: {
          scanType,
          ...(scanType === 'subnet' && subnet ? { subnet } : {})
        }
      };

      await createAssessment(assessmentData);
    } catch (error) {
      throw error;
    }
  };

  if (error) {
    return (
      <ProtectedRoute>
        <div className="space-y-6">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Security Assessments</h1>
            <p className="text-gray-600 mt-2">
              Monitor and manage security assessment results
            </p>
          </div>
          <ErrorState error={error} />
        </div>
      </ProtectedRoute>
    );
  }

  const completedAssessments = assessments.filter(a => a.status === 'COMPLETED');
  const runningAssessments = assessments.filter(a => a.status === 'RUNNING');
  const failedAssessments = assessments.filter(a => a.status === 'FAILED');

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Security Assessments</h1>
            <p className="text-gray-600 mt-2">
              Monitor and manage security assessment results
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
            <Button variant="primary" onClick={handleRunAssessment}>
              <Play className="h-4 w-4 mr-2" />
              Run Assessment
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="bg-gradient-to-r from-blue-50 to-blue-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Assessments</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : assessments.length}
                  </p>
                </div>
                <Shield className="h-12 w-12 text-blue-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-green-50 to-emerald-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Completed</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : completedAssessments.length}
                  </p>
                </div>
                <CheckCircle className="h-12 w-12 text-green-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-yellow-50 to-amber-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Running</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : runningAssessments.length}
                  </p>
                </div>
                <Loader2 className="h-12 w-12 text-yellow-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-red-50 to-red-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Failed</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : failedAssessments.length}
                  </p>
                </div>
                <XCircle className="h-12 w-12 text-red-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Assessments List */}
        {isLoading ? (
          <LoadingSkeleton />
        ) : assessments.length === 0 ? (
          <EmptyState onRunAssessment={handleRunAssessment} />
        ) : (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-900">Recent Assessments</h2>
              <Button variant="ghost" size="sm">
                View All
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {assessments.slice(0, 6).map((assessment) => (
                <AssessmentCard key={assessment.id} assessment={assessment} onDelete={deleteAssessment} />
              ))}
            </div>
          </div>
        )}

        {/* Create Assessment Modal */}
        <CreateAssessmentModal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          agents={agents}
          onCreateAssessment={handleCreateAssessment}
        />
      </div>
    </ProtectedRoute>
  );
}