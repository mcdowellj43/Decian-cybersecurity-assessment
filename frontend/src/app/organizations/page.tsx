'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { useOrganizations } from '@/hooks/useOrganizations';
import { useAuthStore } from '@/store/authStore';
import { Plus, Building2, Users, Monitor, BarChart3 } from 'lucide-react';
// import { toast } from 'react-hot-toast';

export default function OrganizationsPage() {
  const { user } = useAuthStore();
  const { organizations, loading, createOrganization, deleteOrganization } = useOrganizations();
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [formData, setFormData] = useState({ name: '' });
  const [creating, setCreating] = useState(false);

  const isAdmin = user?.role === 'admin';

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.name.trim()) {
      console.error('Organization name is required');
      return;
    }

    setCreating(true);
    try {
      await createOrganization(formData.name.trim());
      setFormData({ name: '' });
      setShowCreateForm(false);
    } catch (err) {
      // Error already handled by hook
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Are you sure you want to delete "${name}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await deleteOrganization(id);
    } catch (err) {
      // Error already handled by hook
    }
  };

  if (loading) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">Loading organizations...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Organizations</h1>
          <p className="text-gray-600">Manage organizations and their settings</p>
        </div>

        {isAdmin && (
          <Button
            onClick={() => setShowCreateForm(true)}
            className="flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Create Organization
          </Button>
        )}
      </div>

      {showCreateForm && (
        <Card className="p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Create New Organization</h3>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
                Organization Name
              </label>
              <Input
                id="name"
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ name: e.target.value })}
                placeholder="Enter organization name"
                disabled={creating}
                required
              />
            </div>
            <div className="flex gap-2">
              <Button
                type="submit"
                disabled={creating || !formData.name.trim()}
              >
                {creating ? 'Creating...' : 'Create Organization'}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setShowCreateForm(false);
                  setFormData({ name: '' });
                }}
                disabled={creating}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Card>
      )}

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {organizations.map((org) => (
          <Card key={org.id} className="p-6">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-100 rounded-lg">
                  <Building2 className="w-6 h-6 text-blue-600" />
                </div>
                <div>
                  <h3 className="font-medium text-gray-900">{org.name}</h3>
                  <p className="text-sm text-gray-500">ID: {org.id}</p>
                </div>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Users className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-600">Users</span>
                </div>
                <span className="text-sm font-medium">{org._count.users}</span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Monitor className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-600">Agents</span>
                </div>
                <span className="text-sm font-medium">{org._count.agents}</span>
              </div>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-600">Assessments</span>
                </div>
                <span className="text-sm font-medium">{org._count.assessments}</span>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-gray-200">
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => window.location.href = `/organizations/${org.id}`}
                  className="flex-1"
                >
                  Manage
                </Button>
                {isAdmin && org.id !== user?.organizationId && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleDelete(org.id, org.name)}
                    className="text-red-600 hover:text-red-700 hover:bg-red-50"
                  >
                    Delete
                  </Button>
                )}
              </div>
            </div>

            <div className="mt-2 text-xs text-gray-500">
              Created {new Date(org.createdAt).toLocaleDateString()}
            </div>
          </Card>
        ))}
      </div>

      {organizations.length === 0 && (
        <Card className="p-12 text-center">
          <Building2 className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">No organizations found</h3>
          <p className="text-gray-600 mb-4">
            {isAdmin ? 'Create your first organization to get started.' : 'Contact your administrator to create organizations.'}
          </p>
          {isAdmin && (
            <Button onClick={() => setShowCreateForm(true)}>
              Create Organization
            </Button>
          )}
        </Card>
      )}
    </div>
  );
}