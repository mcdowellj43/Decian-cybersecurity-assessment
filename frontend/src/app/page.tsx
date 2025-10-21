'use client';
import { useState, useEffect, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator, RiskProgressBar } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useDashboardData } from '@/hooks/useDashboardData';
import { useOrganizationDashboardData } from '@/hooks/useOrganizationDashboardData';
import { useOrganizations } from '@/hooks/useOrganizations';
import { useAuthStore } from '@/store/authStore';
import { Shield, Activity, FileText, AlertTriangle, Loader2, ChevronDown } from 'lucide-react';
import { useRouter } from 'next/navigation';

function LoadingSkeleton() {
  return (
    <div className="animate-pulse">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
        {[1, 2, 3, 4].map((i) => (
          <Card key={i}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <div className="h-4 bg-gray-200 rounded w-24 mb-2"></div>
                  <div className="h-8 bg-gray-200 rounded w-16"></div>
                </div>
                <div className="h-12 w-12 bg-gray-200 rounded"></div>
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
          <AlertTriangle className="h-5 w-5 text-red-600" />
          <p className="text-red-800">Failed to load dashboard data: {error}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function OrganizationRiskScoreCard() {
  const [selectedOrgId, setSelectedOrgId] = useState<string>('');
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const { user } = useAuthStore();
  const { organizations } = useOrganizations();
  const { assessmentStats: orgAssessmentStats, isLoading: orgStatsLoading, refetch } = useOrganizationDashboardData(selectedOrgId || user?.organizationId);

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setShowDropdown(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  const handleOrganizationChange = async (orgId: string) => {
    setSelectedOrgId(orgId);
    setShowDropdown(false);
    await refetch(orgId);
  };

  const displayOrg = selectedOrgId
    ? organizations.find(org => org.id === selectedOrgId)
    : organizations.find(org => org.id === user?.organizationId);

  if (orgStatsLoading && !orgAssessmentStats) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Overall Risk Score by Organization</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-gray-200 rounded w-3/4"></div>
            <div className="h-8 bg-gray-200 rounded"></div>
            <div className="h-4 bg-gray-200 rounded w-1/2"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Overall Risk Score by Organization</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Organization Selector */}
          <div className="relative" ref={dropdownRef}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Choose Organization:
            </label>
            <div className="relative">
              <button
                onClick={() => setShowDropdown(!showDropdown)}
                className="w-full flex items-center justify-between px-3 py-2 border border-gray-300 rounded-md bg-white text-left focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              >
                <span className="truncate">
                  {displayOrg?.name || 'Select Organization'}
                </span>
                <ChevronDown className={`h-4 w-4 text-gray-400 transition-transform ${showDropdown ? 'rotate-180' : ''}`} />
              </button>

              {showDropdown && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg">
                  <div className="py-1">
                    {user?.organizationId && (
                      <button
                        onClick={() => handleOrganizationChange('')}
                        className={`w-full text-left px-3 py-2 hover:bg-gray-100 ${!selectedOrgId ? 'bg-blue-50 text-blue-700' : 'text-gray-900'}`}
                      >
                        {organizations.find(org => org.id === user?.organizationId)?.name} (Current)
                      </button>
                    )}
                    {organizations
                      .filter(org => org.id !== user?.organizationId)
                      .map((org) => (
                        <button
                          key={org.id}
                          onClick={() => handleOrganizationChange(org.id)}
                          className={`w-full text-left px-3 py-2 hover:bg-gray-100 ${selectedOrgId === org.id ? 'bg-blue-50 text-blue-700' : 'text-gray-900'}`}
                        >
                          {org.name}
                        </button>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Risk Score Display */}
          <div className="space-y-4">
            <RiskProgressBar score={orgAssessmentStats?.averageRiskScore || 0} />
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Risk Level</span>
              <RiskIndicator score={orgAssessmentStats?.averageRiskScore || 0} />
            </div>
            {orgStatsLoading && (
              <div className="text-sm text-gray-500 text-center">
                <Loader2 className="h-4 w-4 animate-spin mx-auto mb-1" />
                Loading organization data...
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function Home() {
  const { agentStats, assessmentStats, recentAssessments, isLoading, error } = useDashboardData();
  const router = useRouter();

  if (error) {
    return (
      <ProtectedRoute>
        <div className="space-y-6">
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Security Overview</h1>
            <p className="text-gray-600 mt-2">
              Comprehensive cybersecurity assessment dashboard
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
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Security Overview</h1>
        <p className="text-gray-600 mt-2">
          Comprehensive cybersecurity assessment dashboard
        </p>
      </div>

      {isLoading ? <LoadingSkeleton /> : (
        <>
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gradient-to-r from-blue-50 to-blue-100">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Agents</p>
                <p className="text-3xl font-bold text-gray-900">
                  {agentStats?.recentlyActive || 0}
                </p>
              </div>
              <Activity className="h-12 w-12 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-green-50 to-emerald-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Completed Assessments</p>
                <p className="text-3xl font-bold text-gray-900">
                  {assessmentStats?.statusCounts?.COMPLETED || 0}
                </p>
              </div>
              <Shield className="h-12 w-12 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-orange-50 to-amber-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Recent Assessments</p>
                <p className="text-3xl font-bold text-gray-900">
                  {assessmentStats?.recentAssessments || 0}
                </p>
              </div>
              <AlertTriangle className="h-12 w-12 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-purple-50 to-indigo-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Assessments</p>
                <p className="text-3xl font-bold text-gray-900">
                  {assessmentStats?.totalAssessments || 0}
                </p>
              </div>
              <FileText className="h-12 w-12 text-purple-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <OrganizationRiskScoreCard />

        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAssessments.length > 0 ? (
                recentAssessments.slice(0, 3).map((assessment) => (
                  <div key={assessment.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="font-medium text-gray-900">
                        Assessment {assessment.id.substring(0, 8)}
                      </p>
                      <p className="text-sm text-gray-600">
                        {assessment.agent?.hostname || 'Unknown Agent'}
                      </p>
                    </div>
                    <RiskIndicator
                      score={assessment.overallRiskScore || 0}
                      showScore={false}
                      size="sm"
                    />
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <p>No recent assessments found</p>
                  <p className="text-sm">Run your first assessment to see activity here</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4">
            <Button variant="primary">Run New Assessment</Button>
            <Button
              variant="secondary"
              onClick={() => router.push('/agents')}
            >
              Download Agent
            </Button>
            <Button variant="outline">Generate Report</Button>
            <Button variant="ghost">View All Assessments</Button>
          </div>
        </CardContent>
      </Card>
        </>
      )}
      </div>
    </ProtectedRoute>
  );
}