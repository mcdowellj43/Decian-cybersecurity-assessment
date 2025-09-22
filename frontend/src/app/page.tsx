import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { RiskIndicator, RiskProgressBar } from '@/components/ui/RiskIndicator';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { Shield, Activity, FileText, AlertTriangle } from 'lucide-react';

export default function Home() {
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

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card className="bg-gradient-to-r from-blue-50 to-primary-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Active Agents</p>
                <p className="text-3xl font-bold text-gray-900">12</p>
              </div>
              <Activity className="h-12 w-12 text-primary" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-green-50 to-emerald-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Completed Assessments</p>
                <p className="text-3xl font-bold text-gray-900">156</p>
              </div>
              <Shield className="h-12 w-12 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-orange-50 to-amber-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Critical Findings</p>
                <p className="text-3xl font-bold text-gray-900">8</p>
              </div>
              <AlertTriangle className="h-12 w-12 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-r from-purple-50 to-indigo-50">
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Reports Generated</p>
                <p className="text-3xl font-bold text-gray-900">89</p>
              </div>
              <FileText className="h-12 w-12 text-purple-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Overall Risk Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <RiskProgressBar score={72} />
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Risk Level</span>
                <RiskIndicator score={72} />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">DC Security Check</p>
                  <p className="text-sm text-gray-600">DESKTOP-WIN01</p>
                </div>
                <RiskIndicator level="high" showScore={false} size="sm" />
              </div>
              <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">Password Policy Analysis</p>
                  <p className="text-sm text-gray-600">SERVER-01</p>
                </div>
                <RiskIndicator level="medium" showScore={false} size="sm" />
              </div>
              <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">Windows Update Check</p>
                  <p className="text-sm text-gray-600">WORKSTATION-05</p>
                </div>
                <RiskIndicator level="low" showScore={false} size="sm" />
              </div>
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
            <Button variant="secondary">Download Agent</Button>
            <Button variant="outline">Generate Report</Button>
            <Button variant="ghost">View All Assessments</Button>
          </div>
        </CardContent>
      </Card>
      </div>
    </ProtectedRoute>
  );
}
