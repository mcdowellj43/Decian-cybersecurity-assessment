import { apiClient, handleApiResponse, handleApiError } from './apiClient';

export interface Report {
  id: string;
  assessmentId: string;
  title: string;
  templateVersion: string;
  htmlContent: string;
  organizationName: string;
  createdAt: string;
  assessment?: {
    id: string;
    status: string;
    overallRiskScore: number | null;
    startTime: string;
    endTime: string | null;
    agent: {
      hostname: string;
    };
  };
}

export interface GenerateReportRequest {
  assessmentId: string;
  title?: string;
  includeDetails?: boolean;
  includeExecutiveSummary?: boolean;
}

export interface GetReportsParams {
  assessmentId?: string;
  limit?: number;
  offset?: number;
}

export const reportApi = {
  /**
   * Generate a new report from assessment
   */
  generate: async (data: GenerateReportRequest): Promise<Report> => {
    try {
      const response = await apiClient.post('/reports/generate', data);
      return handleApiResponse<{ report: Report }>(response).report;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get all reports for the organization
   */
  getReports: async (params: GetReportsParams = {}): Promise<{
    reports: Report[];
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  }> => {
    try {
      const queryParams = new URLSearchParams();
      if (params.assessmentId) queryParams.append('assessmentId', params.assessmentId);
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());

      const response = await apiClient.get(`/reports?${queryParams.toString()}`);
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get specific report (JSON format)
   */
  getReport: async (reportId: string): Promise<Report> => {
    try {
      const response = await apiClient.get(`/reports/${reportId}?format=json`);
      return handleApiResponse<{ report: Report }>(response).report;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Download report as HTML
   */
  downloadHTML: async (reportId: string): Promise<string> => {
    try {
      const response = await apiClient.get(`/reports/${reportId}?format=html`, {
        responseType: 'text',
      });
      return response.data;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get report download URL
   */
  getDownloadUrl: (reportId: string, format: 'html' | 'json' = 'html'): string => {
    const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
    return `${baseUrl}/api/reports/${reportId}?format=${format}`;
  },

  /**
   * Delete a report
   */
  delete: async (reportId: string): Promise<void> => {
    try {
      await apiClient.delete(`/reports/${reportId}`);
    } catch (error) {
      throw handleApiError(error);
    }
  },
};