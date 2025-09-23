'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
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
  Mail
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

function ReportCard({ report }: { report: any }) {
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
              <p className="text-sm text-gray-600">{report.description}</p>
            </div>
            <div className="flex items-center space-x-1">
              <RiskIndicator score={report.riskScore} size="sm" />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Created:</span>
              <span className="text-gray-900">{report.createdAt}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Type:</span>
              <span className="text-gray-900">{report.type}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Assessment:</span>
              <span className="text-gray-900">{report.assessmentId}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-600">Size:</span>
              <span className="text-gray-900">{report.size}</span>
            </div>
          </div>

          <div className="flex space-x-2 pt-2">
            <Button variant="outline" size="sm" className="flex-1">
              <Eye className="h-4 w-4 mr-1" />
              Preview
            </Button>
            <Button variant="outline" size="sm">
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

function EmptyState() {
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
            <Button variant="primary">
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

// Mock data for demonstration
const mockReports = [
  {
    id: '1',
    title: 'Executive Security Summary',
    description: 'High-level security overview for leadership team',
    type: 'Executive',
    riskScore: 75,
    createdAt: '2024-03-15',
    assessmentId: 'ASS-001',
    size: '2.3 MB'
  },
  {
    id: '2',
    title: 'Technical Assessment Report',
    description: 'Detailed technical findings and recommendations',
    type: 'Technical',
    riskScore: 82,
    createdAt: '2024-03-14',
    assessmentId: 'ASS-002',
    size: '5.7 MB'
  },
  {
    id: '3',
    title: 'Compliance Audit Report',
    description: 'Regulatory compliance status and gaps',
    type: 'Compliance',
    riskScore: 45,
    createdAt: '2024-03-12',
    assessmentId: 'ASS-003',
    size: '3.1 MB'
  }
];

export default function ReportsPage() {
  const reports = mockReports; // This would come from an API call
  const isLoading = false;
  const error = null;

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
            <Button variant="primary">
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
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
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
                    {isLoading ? '-' : '8'}
                  </p>
                </div>
                <Calendar className="h-12 w-12 text-green-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-purple-50 to-indigo-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Shared</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : '12'}
                  </p>
                </div>
                <Share2 className="h-12 w-12 text-purple-600" />
              </div>
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-orange-50 to-amber-50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-600">Downloaded</p>
                  <p className="text-3xl font-bold text-gray-900">
                    {isLoading ? '-' : '24'}
                  </p>
                </div>
                <Download className="h-12 w-12 text-orange-600" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Reports Grid */}
        {isLoading ? (
          <LoadingSkeleton />
        ) : reports.length === 0 ? (
          <EmptyState />
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
                <ReportCard key={report.id} report={report} />
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
      </div>
    </ProtectedRoute>
  );
}