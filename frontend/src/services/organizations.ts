import { apiClient } from './apiClient';

export interface Organization {
  id: string;
  name: string;
  settings: string;
  createdAt: string;
  updatedAt: string;
  _count: {
    users: number;
    agents: number;
    assessments: number;
  };
}

export interface EnrollmentToken {
  id: string;
  expiresAt: string;
  createdAt: string;
}

export interface EnrollmentTokenWithValue {
  token: string;
  expiresAt: string;
}

export interface CreateOrganizationData {
  name: string;
  settings?: Record<string, any>;
}

export interface UpdateOrganizationData {
  name?: string;
  settings?: Record<string, any>;
}

class OrganizationsService {
  /**
   * Get all organizations (admin only)
   */
  async getOrganizations(): Promise<Organization[]> {
    const response = await apiClient.get<{ data: { organizations: Organization[] } }>('/organizations');
    return response.data.data.organizations;
  }

  /**
   * Get single organization
   */
  async getOrganization(id: string): Promise<Organization> {
    const response = await apiClient.get<{ data: { organization: Organization } }>(`/organizations/${id}`);
    return response.data.data.organization;
  }

  /**
   * Create new organization (admin only)
   */
  async createOrganization(data: CreateOrganizationData): Promise<{
    organization: Organization;
    enrollmentToken: EnrollmentTokenWithValue;
  }> {
    const response = await apiClient.post<{
      data: {
        organization: Organization;
        enrollmentToken: EnrollmentTokenWithValue;
      };
    }>('/organizations', data);
    return response.data.data;
  }

  /**
   * Update organization
   */
  async updateOrganization(id: string, data: UpdateOrganizationData): Promise<Organization> {
    const response = await apiClient.put<{ data: { organization: Organization } }>(`/organizations/${id}`, data);
    return response.data.data.organization;
  }

  /**
   * Delete organization (admin only)
   */
  async deleteOrganization(id: string): Promise<void> {
    await apiClient.delete(`/organizations/${id}`);
  }

  /**
   * Get current enrollment token
   */
  async getEnrollmentToken(id: string): Promise<EnrollmentToken> {
    const response = await apiClient.get<{ data: { enrollmentToken: EnrollmentToken } }>(`/organizations/${id}/enrollment-token`);
    return response.data.data.enrollmentToken;
  }

  /**
   * Regenerate enrollment token
   */
  async regenerateEnrollmentToken(id: string): Promise<EnrollmentTokenWithValue> {
    const response = await apiClient.post<{ data: { enrollmentToken: EnrollmentTokenWithValue } }>(`/organizations/${id}/enrollment-token/regenerate`);
    return response.data.data.enrollmentToken;
  }

  /**
   * Get enrollment token history
   */
  async getEnrollmentTokenHistory(id: string): Promise<EnrollmentToken[]> {
    const response = await apiClient.get<{ data: { tokens: EnrollmentToken[] } }>(`/organizations/${id}/enrollment-token/history`);
    return response.data.data.tokens;
  }
}

export const organizationsService = new OrganizationsService();