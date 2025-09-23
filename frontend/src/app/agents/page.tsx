'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAgents } from '@/hooks/useAgents';
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

function AgentCard({ agent }: { agent: any }) {
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
            <Button variant="outline" size="sm" className="flex-1">
              <Settings className="h-4 w-4 mr-1" />
              Configure
            </Button>
            <Button variant="ghost" size="sm">
              <Trash2 className="h-4 w-4 text-red-600" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState() {
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
            <Button variant="primary">
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
  const { agents, isLoading, error, createAgent, updateAgent, deleteAgent } = useAgents();

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
            <Button variant="primary">
              <Download className="h-4 w-4 mr-2" />
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
          <EmptyState />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {agents.map((agent) => (
              <AgentCard key={agent.id} agent={agent} />
            ))}
          </div>
        )}
      </div>
    </ProtectedRoute>
  );
}