'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useReports } from '@/hooks/useReports';
import { useAssessments } from '@/hooks/useAssessments';
import { Report, reportApi } from '@/services/reportApi';
import { useState } from 'react';
import {
  FileText,
  Download,
  Eye,
  Calendar,
  Building,
  Filter,
  Search,
  Share2,
  PlusCircle,
  MoreVertical,
  Printer,
  Mail,
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
                  <div className="h-4 bg-gray-200 rounded w-48"></div>
                  <div className="h-6 bg-gray-200 rounded w-32"></div>
                </div>
                <div className="h-8 bg-gray-200 rounded w-24"></div>
              </div>
              <div className="h-4 bg-gray-200 rounded w-full"></div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function ReportCard({ report, onDownload }: { report: Report; onDownload: (reportId: string) => void }) {
  const handleDownload = async () => {
    try {
      await onDownload(report.id);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  return (
    <Card className="hover:shadow-md transition-shadow">
      <CardContent className="p-6">
        <div className="space-y-4">
          <div className="flex justify-between items-start">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <FileText className="h-5 w-5 text-blue-600" />
                <h3 className="font-semibold text-gray-900">{report.title}</h3>
              </div>
              <p className="text-sm text-gray-600">
                Assessment #{report.assessmentId.substring(0, 8)} - {report.assessment?.agent?.hostname || 'Unknown'}
              </p>
            </div>
            <div className="flex items-center space-x-1">
              {report.assessment?.overallRiskScore && (
                <RiskIndicator score={report.assessment.overallRiskScore} size="sm" />
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Created:</span>
              <span className="text-gray-900">
                {new Date(report.createdAt).toLocaleDateString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Version:</span>
              <span className="text-gray-900">{report.templateVersion}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Assessment:</span>
              <span className="text-gray-900">#{report.assessmentId.substring(0, 8)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Organization:</span>
              <span className="text-gray-900">{report.organizationName}</span>
            </div>
          </div>

          <div className="flex space-x-2 pt-2">
            <Button variant="outline" size="sm" className="flex-1">
              <Eye className="h-4 w-4 mr-1" />
              Preview
            </Button>
            <Button variant="outline" size="sm" onClick={handleDownload}>
              <Download className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm">
              <Share2 className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm">
              <MoreVertical className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function GenerateReportModal({
  isOpen,
  onClose,
  onGenerate
}: {
  isOpen: boolean;
  onClose: () => void;
  onGenerate: (assessmentId: string) => void;
}) {
  const { assessments, isLoading } = useAssessments({ status: 'COMPLETED' });
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAssessmentId) return;

    await onGenerate(selectedAssessmentId);
    onClose();
    setSelectedAssessmentId('');
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white rounded-lg max-w-md w-full">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-gray-900">Generate Security Report</h2>
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
              Select Completed Assessment
            </label>
            {isLoading ? (
              <div className="text-center py-4">Loading assessments...</div>
            ) : assessments.length === 0 ? (
              <div className="text-center py-8">
                <FileText className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <p className="text-gray-600 text-sm">No completed assessments found</p>
                <p className="text-gray-500 text-xs">Run an assessment first to generate reports</p>
              </div>
            ) : (
              <select
                value={selectedAssessmentId}
                onChange={(e) => setSelectedAssessmentId(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              >
                <option value="">Choose an assessment...</option>
                {assessments.map((assessment) => (
                  <option key={assessment.id} value={assessment.id}>
                    {assessment.agent?.hostname || 'Unknown'} - {new Date(assessment.createdAt).toLocaleDateString()}
                  </option>
                ))}
              </select>
            )}
          </div>

          <div className="flex space-x-3 pt-4">
            <Button type="button" variant="outline" onClick={onClose} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              className="flex-1"
              disabled={!selectedAssessmentId || assessments.length === 0}
            >
              <FileText className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function EmptyState({ onGenerateReport }: { onGenerateReport: () => void }) {
  return (
    <Card className="border-dashed border-2 border-gray-300">
      <CardContent className="p-12">
        <div className="text-center space-y-4">
          <FileText className="h-16 w-16 text-gray-400 mx-auto" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900">No Reports Generated</h3>
            <p className="text-gray-600 max-w-md mx-auto">
              Generate your first security report from completed assessments to share insights.
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="primary" onClick={onGenerateReport}>
              <PlusCircle className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
            <Button variant="outline">View Templates</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function ReportsPage() {
  const { reports, isLoading, error, downloadHTML, refetch } = useReports();
  const [showGenerateModal, setShowGenerateModal] = useState(false);

  // Calculate this month's reports
  const thisMonth = new Date();
  const thisMonthReports = reports.filter(report => {
    const reportDate = new Date(report.createdAt);
    return reportDate.getMonth() === thisMonth.getMonth() &&
           reportDate.getFullYear() === thisMonth.getFullYear();
  }).length;

  const handleDownload = async (reportId: string) => {
    try {
      await downloadHTML(reportId);
    } catch (error) {
      console.error('Failed to download report:', error);
      // You could add toast notification here
    }
  };

  const handleGenerateReport = async (assessmentId: string) => {
    try {
      const report = await reportApi.generate({
        assessmentId,
        title: `Security Assessment Report - ${new Date().toLocaleDateString()}`,
        includeDetails: true,
        includeExecutiveSummary: true
      });

      // Refresh the reports list
      await refetch();

      // Auto-download the new report
      await downloadHTML(report.id);
    } catch (error) {
      console.error('Failed to generate report:', error);
      // You could add toast notification here
    }
  };

  const handleShowGenerateModal = () => {
    setShowGenerateModal(true);
  };

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex justify-between items-start">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">Security Reports</h1>
            <p className="text-gray-600 mt-2">
              Generate and manage security assessment reports
            </p>
          </div>
          <div className="space-x-3">
            <Button variant="outline">
              <Filter className="h-4 w-4 mr-2" />
              Filter
            </Button>
            <Button variant="outline">
              <Printer className="h-4 w-4 mr-2" />
              Print
            </Button>
            <Button variant="primary" onClick={handleShowGenerateModal}>
              <PlusCircle className="h-4 w-4 mr-2" />
              Generate Report
            </Button>
          </div>
        </div>

        {/* Search and Filters */}
        <Card>
          <CardContent className="p-6">
            <div className="flex space-x-4">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search reports..."
                  className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
              <select className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                <option>All Types</option>
                <option>Executive</option>
                <option>Technical</option>
                <option>Compliance</option>
              </select>
              <select className="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                <option>Last 30 days</option>
                <option>Last 7 days</option>
                <option>Last year</option>
                <option>All time</option>
              </select>
            </div>
          </CardContent>
        </Card>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card className="bg-gradient-to-r from-blue-50 to-blue-100">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Total Reports</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : reports.length}
                  </p>
                </div>
                <FileText className="h-12 w-12 text-blue-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-green-50 to-emerald-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">This Month</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : thisMonthReports}
                  </p>
                </div>
                <Calendar className="h-12 w-12 text-green-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Reports Grid */}
        {error ? (
          <Card className="border-red-200 bg-red-50">
            <CardContent className="p-6">
              <div className="text-center">
                <p className="text-red-800">Failed to load reports: {error}</p>
                <Button variant="outline" onClick={() => window.location.reload()} className="mt-4">
                  Retry
                </Button>
              </div>
            </CardContent>
          </Card>
        ) : isLoading ? (
          <LoadingSkeleton />
        ) : reports.length === 0 ? (
          <EmptyState onGenerateReport={handleShowGenerateModal} />
        ) : (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-900">Recent Reports</h2>
              <Button variant="ghost" size="sm">
                View All
              </Button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {reports.map((report) => (
                <ReportCard key={report.id} report={report} onDownload={handleDownload} />
              ))}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Button variant="outline" className="justify-start">
                <Building className="h-4 w-4 mr-2" />
                Executive Summary
              </Button>
              <Button variant="outline" className="justify-start">
                <FileText className="h-4 w-4 mr-2" />
                Technical Report
              </Button>
              <Button variant="outline" className="justify-start">
                <Mail className="h-4 w-4 mr-2" />
                Email Report
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Generate Report Modal */}
        <GenerateReportModal
          isOpen={showGenerateModal}
          onClose={() => setShowGenerateModal(false)}
          onGenerate={handleGenerateReport}
        />
      </div>
    </ProtectedRoute>
  );
}