'use client';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { useAuthStore } from '@/store/authStore';
import {
  User,
  Building,
  Shield,
  Bell,
  Key,
  Mail,
  Globe,
  Database,
  Download,
  Upload,
  Trash2,
  Save,
  AlertTriangle
} from 'lucide-react';

function SettingsSection({
  title,
  description,
  children
}: {
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <span>{title}</span>
        </CardTitle>
        <p className="text-sm text-gray-600">{description}</p>
      </CardHeader>
      <CardContent>
        {children}
      </CardContent>
    </Card>
  );
}

export default function SettingsPage() {
  const { user } = useAuthStore();

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-600 mt-2">
            Manage your account, organization, and platform preferences
          </p>
        </div>

        {/* Settings Sections */}
        <div className="space-y-6">
          {/* User Profile */}
          <SettingsSection
            title="User Profile"
            description="Update your personal information and account details"
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Full Name
                  </label>
                  <Input
                    type="text"
                    defaultValue={user?.name || ''}
                    placeholder="Enter your full name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email Address
                  </label>
                  <Input
                    type="email"
                    defaultValue={user?.email || ''}
                    placeholder="Enter your email"
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Role
                  </label>
                  <Input
                    type="text"
                    value={user?.role || ''}
                    disabled
                    className="bg-gray-50"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Organization
                  </label>
                  <Input
                    type="text"
                    value={user?.organizationName || ''}
                    disabled
                    className="bg-gray-50"
                  />
                </div>
              </div>
              <div className="flex space-x-3">
                <Button variant="primary">
                  <Save className="h-4 w-4 mr-2" />
                  Save Changes
                </Button>
                <Button variant="outline">Cancel</Button>
              </div>
            </div>
          </SettingsSection>

          {/* Security Settings */}
          <SettingsSection
            title="Security"
            description="Manage your password and security preferences"
          >
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Current Password
                </label>
                <Input
                  type="password"
                  placeholder="Enter current password"
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    New Password
                  </label>
                  <Input
                    type="password"
                    placeholder="Enter new password"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Confirm Password
                  </label>
                  <Input
                    type="password"
                    placeholder="Confirm new password"
                  />
                </div>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <Shield className="h-5 w-5 text-blue-600" />
                  <div>
                    <p className="font-medium">Two-Factor Authentication</p>
                    <p className="text-sm text-gray-600">Add an extra layer of security</p>
                  </div>
                </div>
                <Button variant="outline" size="sm">Enable</Button>
              </div>
              <div className="flex space-x-3">
                <Button variant="primary">
                  <Key className="h-4 w-4 mr-2" />
                  Update Password
                </Button>
              </div>
            </div>
          </SettingsSection>

          {/* Organization Settings */}
          <SettingsSection
            title="Organization"
            description="Manage organization settings and preferences"
          >
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Organization Name
                </label>
                  <Input
                    type="text"
                    defaultValue={user?.organizationName || ''}
                    placeholder="Enter organization name"
                  />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Default Assessment Frequency
                  </label>
                  <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option>Weekly</option>
                    <option>Monthly</option>
                    <option>Quarterly</option>
                    <option>Manual</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Risk Threshold
                  </label>
                  <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500">
                    <option>Low (0-30)</option>
                    <option>Medium (30-70)</option>
                    <option>High (70-100)</option>
                  </select>
                </div>
              </div>
              <div className="flex space-x-3">
                <Button variant="primary">
                  <Building className="h-4 w-4 mr-2" />
                  Save Organization Settings
                </Button>
              </div>
            </div>
          </SettingsSection>

          {/* Notifications */}
          <SettingsSection
            title="Notifications"
            description="Configure how you receive alerts and updates"
          >
            <div className="space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Mail className="h-5 w-5 text-blue-600" />
                    <div>
                      <p className="font-medium">Email Notifications</p>
                      <p className="text-sm text-gray-600">Receive assessment results via email</p>
                    </div>
                  </div>
                  <input type="checkbox" className="rounded border-gray-300" defaultChecked />
                </div>
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Bell className="h-5 w-5 text-yellow-600" />
                    <div>
                      <p className="font-medium">Critical Alerts</p>
                      <p className="text-sm text-gray-600">Immediate notifications for high-risk findings</p>
                    </div>
                  </div>
                  <input type="checkbox" className="rounded border-gray-300" defaultChecked />
                </div>
                <div className="flex items-center justify-between p-3 border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Globe className="h-5 w-5 text-green-600" />
                    <div>
                      <p className="font-medium">Weekly Reports</p>
                      <p className="text-sm text-gray-600">Summary of security posture changes</p>
                    </div>
                  </div>
                  <input type="checkbox" className="rounded border-gray-300" />
                </div>
              </div>
              <div className="flex space-x-3">
                <Button variant="primary">
                  <Bell className="h-4 w-4 mr-2" />
                  Save Notification Settings
                </Button>
              </div>
            </div>
          </SettingsSection>

          {/* Data Management */}
          <SettingsSection
            title="Data Management"
            description="Export, import, and manage your data"
          >
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button variant="outline" className="justify-start">
                  <Download className="h-4 w-4 mr-2" />
                  Export Data
                </Button>
                <Button variant="outline" className="justify-start">
                  <Upload className="h-4 w-4 mr-2" />
                  Import Data
                </Button>
                <Button variant="outline" className="justify-start">
                  <Database className="h-4 w-4 mr-2" />
                  Backup Settings
                </Button>
              </div>
              <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start space-x-3">
                  <AlertTriangle className="h-5 w-5 text-red-600 mt-0.5" />
                  <div>
                    <h4 className="font-medium text-red-900">Danger Zone</h4>
                    <p className="text-sm text-red-700 mb-3">
                      These actions cannot be undone. Please be careful.
                    </p>
                    <Button variant="outline" className="border-red-300 text-red-700 hover:bg-red-50">
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete Organization
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </SettingsSection>
        </div>
      </div>
    </ProtectedRoute>
  );
}