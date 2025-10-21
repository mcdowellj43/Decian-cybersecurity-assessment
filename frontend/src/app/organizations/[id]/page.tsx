'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { useOrganization } from '@/hooks/useOrganizations';
import { useAuthStore } from '@/store/authStore';
import {
  Building2,
  Key,
  Clipboard,
  RefreshCw,
  Check,
  AlertTriangle
} from 'lucide-react';
// import { toast } from 'react-hot-toast';

interface AgentSetupCommandProps {
  organizationId: string;
  enrollmentToken?: string;
}

function AgentSetupCommand({ organizationId, enrollmentToken }: AgentSetupCommandProps) {
  const [copied, setCopied] = useState(false);
  const serverUrl = process.env.NODE_ENV === 'development'
    ? 'http://localhost:3001'
    : window.location.origin.replace(':3000', ':3001');

  const setupCommand = enrollmentToken
    ? `decian-agent.exe setup --server "${serverUrl}" --org-id "${organizationId}" --enroll-token "${enrollmentToken}"`
    : `# Generate an enrollment token first`;

  const copyToClipboard = async () => {
    if (!enrollmentToken) {
      console.error('No enrollment token available');
      return;
    }

    try {
      await navigator.clipboard.writeText(setupCommand);
      setCopied(true);
      console.log('Command copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy command');
    }
  };

  return (
    <Card className="p-6">
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 bg-green-100 rounded-lg">
          <Clipboard className="w-6 h-6 text-green-600" />
        </div>
        <div>
          <h3 className="font-medium text-gray-900">Agent Setup Command</h3>
          <p className="text-sm text-gray-600">Use this command to register new agents</p>
        </div>
      </div>

      <div className="bg-gray-900 text-gray-100 p-4 rounded-lg font-mono text-sm overflow-x-auto">
        <pre className="whitespace-pre-wrap break-all">{setupCommand}</pre>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <Button
          onClick={copyToClipboard}
          disabled={!enrollmentToken}
          size="sm"
          className="flex items-center gap-2"
        >
          {copied ? (
            <>
              <Check className="w-4 h-4" />
              Copied!
            </>
          ) : (
            <>
              <Clipboard className="w-4 h-4" />
              Copy Command
            </>
          )}
        </Button>

        {!enrollmentToken && (
          <div className="flex items-center gap-2 text-sm text-amber-600">
            <AlertTriangle className="w-4 h-4" />
            Generate a token first
          </div>
        )}
      </div>

      <div className="mt-4 p-4 bg-blue-50 rounded-lg text-sm">
        <h4 className="font-medium text-blue-900 mb-2">Setup Instructions:</h4>
        <ol className="list-decimal list-inside space-y-1 text-blue-800">
          <li>Download the agent executable to your Windows machine</li>
          <li>Open Command Prompt or PowerShell as Administrator</li>
          <li>Navigate to the directory containing decian-agent.exe</li>
          <li>Run the setup command above</li>
          <li>Start the agent with: <code className="bg-blue-100 px-1 rounded">decian-agent.exe run</code></li>
        </ol>
      </div>
    </Card>
  );
}

export default function OrganizationDetailPage() {
  const params = useParams();
  const organizationId = params?.id as string;
  const { user } = useAuthStore();
  const { organization, loading, regenerateEnrollmentToken } = useOrganization(organizationId);
  const [currentToken, setCurrentToken] = useState<string>('');
  const [tokenExpiry, setTokenExpiry] = useState<string>('');
  const [regenerating, setRegenerating] = useState(false);

  const canAccess = user?.role === 'admin' || user?.organizationId === organizationId;

  useEffect(() => {
    // Get current enrollment token on page load
    if (organizationId && canAccess) {
      // This would normally come from the backend, but we'll handle token generation manually
    }
  }, [organizationId, canAccess]);

  const handleRegenerateToken = async () => {
    setRegenerating(true);
    try {
      const tokenData = await regenerateEnrollmentToken();
      if (tokenData) {
        setCurrentToken(tokenData.token);
        setTokenExpiry(tokenData.expiresAt);
      }
    } catch (err) {
      // Error handled by hook
    } finally {
      setRegenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">Loading organization...</div>
        </div>
      </div>
    );
  }

  if (!organization) {
    return (
      <div className="p-6">
        <Card className="p-8 text-center">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Organization Not Found</h3>
          <p className="text-gray-600">The requested organization could not be found or you don&apos;t have permission to access it.</p>
        </Card>
      </div>
    );
  }

  if (!canAccess) {
    return (
      <div className="p-6">
        <Card className="p-8 text-center">
          <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Access Denied</h3>
          <p className="text-gray-600">You don&apos;t have permission to access this organization.</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-100 rounded-lg">
            <Building2 className="w-8 h-8 text-blue-600" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">{organization.name}</h1>
            <p className="text-gray-600">Organization ID: {organization.id}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 bg-purple-100 rounded-lg">
              <Building2 className="w-6 h-6 text-purple-600" />
            </div>
            <div>
              <h3 className="font-medium text-gray-900">Organization Details</h3>
              <p className="text-sm text-gray-600">Basic information and statistics</p>
            </div>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Name</label>
              <Input value={organization.name} disabled />
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">{organization._count.users}</div>
                <div className="text-sm text-gray-600">Users</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">{organization._count.agents}</div>
                <div className="text-sm text-gray-600">Agents</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600">{organization._count.assessments}</div>
                <div className="text-sm text-gray-600">Assessments</div>
              </div>
            </div>

            <div className="pt-4 border-t border-gray-200">
              <div className="text-sm text-gray-600">
                <div>Created: {new Date(organization.createdAt).toLocaleString()}</div>
                <div>Updated: {new Date(organization.updatedAt).toLocaleString()}</div>
              </div>
            </div>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-amber-100 rounded-lg">
                <Key className="w-6 h-6 text-amber-600" />
              </div>
              <div>
                <h3 className="font-medium text-gray-900">Enrollment Token</h3>
                <p className="text-sm text-gray-600">Generate tokens for agent registration</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            {currentToken ? (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Current Token</label>
                <div className="bg-gray-50 p-3 rounded-lg font-mono text-sm break-all border">
                  {currentToken}
                </div>
                <div className="mt-2 text-sm text-gray-600">
                  Expires: {new Date(tokenExpiry).toLocaleString()}
                </div>
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <Key className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                <p>No active enrollment token</p>
              </div>
            )}

            <Button
              onClick={handleRegenerateToken}
              disabled={regenerating}
              className="w-full flex items-center justify-center gap-2"
            >
              <RefreshCw className={`w-4 h-4 ${regenerating ? 'animate-spin' : ''}`} />
              {regenerating ? 'Generating...' : (currentToken ? 'Regenerate Token' : 'Generate Token')}
            </Button>

            <div className="p-3 bg-yellow-50 rounded-lg text-sm text-yellow-800">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                <div>
                  <div className="font-medium">Security Note</div>
                  <div>Tokens expire in 15 minutes and can only be used once. Generate a new token for each agent registration.</div>
                </div>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <AgentSetupCommand
        organizationId={organizationId}
        enrollmentToken={currentToken}
      />
    </div>
  );
}