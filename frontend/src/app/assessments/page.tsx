'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAssessments } from '@/hooks/useAssessments';
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
  Loader2
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

function EmptyState() {
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
            <Button variant="primary">
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

export default function AssessmentsPage() {
  const { assessments, isLoading, error, createAssessment, deleteAssessment } = useAssessments();

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
            <Button variant="primary">
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
          <EmptyState />
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
      </div>
    </ProtectedRoute>
  );
}