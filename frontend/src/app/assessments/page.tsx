'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAssessments } from '@/hooks/useAssessments';
import { useAgents } from '@/hooks/useAgents';
import { useState } from 'react';
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
  X
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

function AssessmentCard({ assessment }: { assessment: any }) {
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
            <Button variant="outline" size="sm" className="flex-1">
              <FileText className="h-4 w-4 mr-1" />
              View Details
            </Button>
            {assessment.status === 'COMPLETED' && (
              <Button variant="ghost" size="sm">
                <Download className="h-4 w-4" />
              </Button>
            )}
            <Button variant="ghost" size="sm">
              <MoreVertical className="h-4 w-4" />
            </Button>
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
  onCreateAssessment: (agentId: string) => void;
}) {
  const [selectedAgentId, setSelectedAgentId] = useState<string>('');
  const [isCreating, setIsCreating] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAgentId) return;

    setIsCreating(true);
    try {
      await onCreateAssessment(selectedAgentId);
      onClose();
      setSelectedAgentId('');
    } catch (error) {
      console.error('Failed to create assessment:', error);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-md w-full">
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

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
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

          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <h4 className="font-medium text-blue-900 mb-2">Assessment Modules</h4>
            <div className="text-sm text-blue-800 space-y-1">
              <div>• Accounts Bypass Password Policy</div>
              <div>• Domain Controller Open Ports Check</div>
              <div>• DNS Configuration Check</div>
              <div>• End-of-Life Software Check</div>
              <div>• Enabled Inactive Accounts</div>
              <div>• Network Protocols Check</div>
              <div>• PowerShell Execution Policy Check</div>
              <div>• Service Accounts Domain Admin</div>
              <div>• Privileged Accounts No Expire</div>
              <div>• Windows Feature Security Check</div>
              <div>• Windows Firewall Status Check</div>
              <div>• Windows Update Check</div>
              <div>• Password Crack</div>
              <div>• Kerberoasted Accounts</div>
              <div>• SMB Signing Check</div>
            </div>
          </div>

          <div className="flex space-x-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              className="flex-1"
              disabled={!selectedAgentId || isCreating || agents.length === 0}
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

  const handleCreateAssessment = async (agentId: string) => {
    try {
      await createAssessment({
        agentId,
        modules: [
          'ACCOUNTS_BYPASS_PASS_POLICY',
          'DC_OPEN_PORTS_CHECK',
          'DNS_CONFIG_CHECK',
          'EOL_SOFTWARE_CHECK',
          'ENABLED_INACTIVE_ACCOUNTS',
          'NETWORK_PROTOCOLS_CHECK',
          'PSHELL_EXEC_POLICY_CHECK',
          'SERVICE_ACCOUNTS_DOMAIN_ADMIN',
          'PRIVILEGED_ACCOUNTS_NO_EXPIRE',
          'WIN_FEATURE_SECURITY_CHECK',
          'WIN_FIREWALL_STATUS_CHECK',
          'WIN_UPDATE_CHECK',
          'PASSWORD_CRACK',
          'KERBEROASTED_ACCOUNTS',
          'SMB_SIGNING_CHECK'
        ]
      });
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
                <AssessmentCard key={assessment.id} assessment={assessment} />
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