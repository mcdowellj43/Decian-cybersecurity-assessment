import { useState, useEffect } from 'react';
import { organizationsService, Organization, EnrollmentTokenWithValue } from '@/services/organizations';
// import { toast } from 'react-hot-toast';

export function useOrganizations() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchOrganizations = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await organizationsService.getOrganizations();
      setOrganizations(data);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to fetch organizations';
      setError(errorMessage);
      console.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrganizations();
  }, []);

  const createOrganization = async (name: string, settings?: Record<string, any>) => {
    try {
      const result = await organizationsService.createOrganization({ name, settings });
      setOrganizations(prev => [result.organization, ...prev]);
      console.log('Organization created successfully');
      return result;
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to create organization';
      console.error(errorMessage);
      throw err;
    }
  };

  const updateOrganization = async (id: string, name?: string, settings?: Record<string, any>) => {
    try {
      const updated = await organizationsService.updateOrganization(id, { name, settings });
      setOrganizations(prev => prev.map(org => org.id === id ? updated : org));
      console.log('Organization updated successfully');
      return updated;
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to update organization';
      console.error(errorMessage);
      throw err;
    }
  };

  const deleteOrganization = async (id: string) => {
    try {
      await organizationsService.deleteOrganization(id);
      setOrganizations(prev => prev.filter(org => org.id !== id));
      console.log('Organization deleted successfully');
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to delete organization';
      console.error(errorMessage);
      throw err;
    }
  };

  return {
    organizations,
    loading,
    error,
    fetchOrganizations,
    createOrganization,
    updateOrganization,
    deleteOrganization,
  };
}

export function useOrganization(id: string) {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchOrganization = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await organizationsService.getOrganization(id);
      setOrganization(data);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to fetch organization';
      setError(errorMessage);
      console.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchOrganization();
    }
  }, [id]);

  const regenerateEnrollmentToken = async (): Promise<EnrollmentTokenWithValue | null> => {
    try {
      const token = await organizationsService.regenerateEnrollmentToken(id);
      console.log('Enrollment token regenerated successfully');
      return token;
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to regenerate enrollment token';
      console.error(errorMessage);
      return null;
    }
  };

  return {
    organization,
    loading,
    error,
    fetchOrganization,
    regenerateEnrollmentToken,
  };
}