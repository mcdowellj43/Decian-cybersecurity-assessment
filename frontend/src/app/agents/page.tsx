'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAgents } from '@/hooks/useAgents';
import { agentApi } from '@/services/agentApi';
import { useState } from 'react';
import {
  Server,
  Activity,
  Wifi,
  WifiOff,
  AlertCircle,
  Download,
  Settings,
  Trash2,
  Loader2
} from 'lucide-react';

function LoadingSkeleton() {
  return (
    <div className="animate-pulse">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {[1, 2, 3].map((i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="space-y-4">
                <div className="h-4 bg-gray-200 rounded w-3/4"></div>
                <div className="h-6 bg-gray-200 rounded w-1/2"></div>
                <div className="h-4 bg-gray-200 rounded w-full"></div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

function ErrorState({ error }: { error: string }) {
  return (
    <Card className="border-red-200 bg-red-50">
      <CardContent className="p-6">
        <div className="flex items-center space-x-2">
          <AlertCircle className="h-5 w-5 text-red-600" />
          <p className="text-red-800">Failed to load agents: {error}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function AgentCard({ agent, onConfigure, onDelete, isDeleting }: { agent: any; onConfigure: (agent: any) => void; onDelete: (agent: any) => void; isDeleting: boolean }) {
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'ONLINE':
        return <Wifi className="h-5 w-5 text-green-600" />;
      case 'OFFLINE':
        return <WifiOff className="h-5 w-5 text-gray-600" />;
      case 'ERROR':
        return <AlertCircle className="h-5 w-5 text-red-600" />;
      default:
        return <WifiOff className="h-5 w-5 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ONLINE':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'OFFLINE':
        return 'text-gray-600 bg-gray-50 border-gray-200';
      case 'ERROR':
        return 'text-red-600 bg-red-50 border-red-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-6">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Server className="h-8 w-8 text-blue-600" />
              <div>
                <h3 className="font-semibold text-gray-900">{agent.hostname}</h3>
                <p className="text-sm text-gray-600">Version {agent.version}</p>
              </div>
            </div>
            <div className={`flex items-center space-x-1 px-2 py-1 rounded-full border ${getStatusColor(agent.status)}`}>
              {getStatusIcon(agent.status)}
              <span className="text-xs font-medium">{agent.status}</span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Last Seen:</span>
              <span className="text-gray-900">
                {agent.lastSeen
                  ? new Date(agent.lastSeen).toLocaleDateString()
                  : 'Never'
                }
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600">Assessments:</span>
              <span className="text-gray-900">{agent.assessments?.length || 0}</span>
            </div>
          </div>

          <div className="flex space-x-2 pt-2">
            <Button variant="outline" size="sm" className="flex-1" onClick={() => onConfigure(agent)}>
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onDelete(agent)}
              disabled={isDeleting}
            >
              {isDeleting ? (
                <Loader2 className="h-4 w-4 text-red-600 animate-spin" />
              ) : (
                <Trash2 className="h-4 w-4 text-red-600" />
              )}
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ConfigurationModal({
  isOpen,
  onClose,
  agent
}: {
  isOpen: boolean;
  onClose: () => void;
  agent: any;
}) {
  if (!isOpen || !agent) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-bold text-gray-900">Configure Agent</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Agent Information</h3>
              <div className="bg-gray-50 border rounded-lg p-4 space-y-2">
                <div className="flex justify-between">
                  <span className="text-gray-600">Hostname:</span>
                  <span className="text-gray-900">{agent.hostname}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Version:</span>
                  <span className="text-gray-900">{agent.version}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Status:</span>
                  <span className="text-gray-900">{agent.status}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Last Seen:</span>
                  <span className="text-gray-900">
                    {agent.lastSeen
                      ? new Date(agent.lastSeen).toLocaleString()
                      : 'Never'
                    }
                  </span>
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">Security Modules</h3>
              <div className="bg-gray-50 border rounded-lg p-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-sm">
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Misconfiguration Discovery</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Weak Password Detection</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Data Exposure Check</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Phishing Exposure Indicators</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Patch & Update Status</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Elevated Permissions Report</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Excessive Sharing Risks</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Password Policy Weakness</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>Open Service/Port ID</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                    <span>User Behavior Risk Signals</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="p-6 border-t border-gray-200 bg-gray-50">
          <div className="flex justify-end space-x-3">
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
            <Button variant="primary">
              Save Changes
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function EmptyState({ onDownloadClick }: { onDownloadClick: () => void }) {
  return (
    <Card className="border-dashed border-2 border-gray-300">
      <CardContent className="p-12">
        <div className="text-center space-y-4">
          <Server className="h-16 w-16 text-gray-400 mx-auto" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">No Agents Deployed</h3>
            <p className="text-gray-600 max-w-md mx-auto">
              Download and deploy agents on your systems to start security assessments.
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="primary" onClick={onDownloadClick}>
              <Download className="h-4 w-4 mr-2" />
              Download Agent
            </Button>
            <Button variant="outline">View Documentation</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function AgentsPage() {
  const { agents, isLoading, error, refetch } = useAgents();
  const [isDownloading, setIsDownloading] = useState(false);
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<any>(null);
  const [isDeleting, setIsDeleting] = useState<string | null>(null);

  const handleConfigureAgent = (agent: any) => {
    setSelectedAgent(agent);
    setShowConfigModal(true);
  };

  const handleDeleteAgent = async (agent: any) => {
    const confirmDelete = window.confirm(
      `Are you sure you want to delete agent "${agent.hostname}"? This action cannot be undone.`
    );

    if (!confirmDelete) {
      return;
    }

    setIsDeleting(agent.id);
    try {
      await agentApi.deleteAgent(agent.id);
      await refetch(); // Refresh the agents list
    } catch (error) {
      console.error('Failed to delete agent:', error);
      alert('Failed to delete agent. Please try again.');
    } finally {
      setIsDeleting(null);
    }
  };

  const handleDownloadClick = async () => {
    setIsDownloading(true);
    try {
      // Get the auth token in the same way apiClient does
      let authToken = '';
      if (typeof window !== 'undefined') {
        const authStorage = localStorage.getItem('auth-storage');
        if (authStorage) {
          try {
            const { state } = JSON.parse(authStorage);
            if (state?.tokens?.accessToken) {
              authToken = state.tokens.accessToken;
            }
          } catch (error) {
            console.error('Error parsing auth storage:', error);
          }
        }
      }

      // Use the proper API base URL (port 3001)
      const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
      const response = await fetch(`${API_BASE_URL}/api/agents/download`, {
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
      });

      if (!response.ok) {
        const errorMessage = await response.text();
        throw new Error(errorMessage || 'Download failed');
      }

      const contentDisposition = response.headers.get('content-disposition');
      let filename = 'decian-agent.exe';
      if (contentDisposition) {
        const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
        if (filenameMatch) {
          filename = filenameMatch[1];
        }
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to download agent:', error);
      alert('Download failed. Please try again.');
    } finally {
      setIsDownloading(false);
    }
  };

  if (error) {
    return (
      <ProtectedRoute>
        <div className="space-y-6">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Agent Management</h1>
            <p className="text-gray-600 mt-2">
              Monitor and manage deployed security assessment agents
            </p>
          </div>
          <ErrorState error={error} />
        </div>
      </ProtectedRoute>
    );
  }

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Agent Management</h1>
            <p className="text-gray-600 mt-2">
              Monitor and manage deployed security assessment agents
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="outline">
              <Activity className="h-4 w-4 mr-2" />
              Refresh Status
            </Button>
            <Button
              variant="primary"
              onClick={handleDownloadClick}
              disabled={isDownloading}
            >
              {isDownloading ? (
                <Loader2 className="h-4 w-4 mr-2 animate-spin" />
              ) : (
                <Download className="h-4 w-4 mr-2" />
              )}
              Download Agent
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <Card className="bg-gradient-to-r from-blue-50 to-blue-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Agents</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : agents.length}
                  </p>
                </div>
                <Server className="h-12 w-12 text-blue-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-green-50 to-emerald-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Online</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : agents.filter(a => a.status === 'ONLINE').length}
                  </p>
                </div>
                <Wifi className="h-12 w-12 text-green-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-gray-50 to-gray-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Offline</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : agents.filter(a => a.status === 'OFFLINE').length}
                  </p>
                </div>
                <WifiOff className="h-12 w-12 text-gray-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-red-50 to-red-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Errors</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : agents.filter(a => a.status === 'ERROR').length}
                  </p>
                </div>
                <AlertCircle className="h-12 w-12 text-red-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Agents Grid */}
        {isLoading ? (
          <LoadingSkeleton />
        ) : agents.length === 0 ? (
          <EmptyState onDownloadClick={handleDownloadClick} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {agents.map((agent) => (
              <AgentCard
                key={agent.id}
                agent={agent}
                onConfigure={handleConfigureAgent}
                onDelete={handleDeleteAgent}
                isDeleting={isDeleting === agent.id}
              />
            ))}
          </div>
        )}

        {/* Configuration Modal */}
        <ConfigurationModal
          isOpen={showConfigModal}
          onClose={() => {
            setShowConfigModal(false);
            setSelectedAgent(null);
          }}
          agent={selectedAgent}
        />
      </div>
    </ProtectedRoute>
  );
}