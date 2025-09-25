import { apiClient, handleApiResponse, handleApiError } from './apiClient';

export type CheckType =
  | 'MISCONFIGURATION_DISCOVERY'
  | 'WEAK_PASSWORD_DETECTION'
  | 'DATA_EXPOSURE_CHECK'
  | 'PHISHING_EXPOSURE_INDICATORS'
  | 'PATCH_UPDATE_STATUS'
  | 'ELEVATED_PERMISSIONS_REPORT'
  | 'EXCESSIVE_SHARING_RISKS'
  | 'PASSWORD_POLICY_WEAKNESS'
  | 'OPEN_SERVICE_PORT_ID'
  | 'USER_BEHAVIOR_RISK_SIGNALS';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AssessmentStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface AssessmentResult {
  id: string;
  checkType: CheckType;
  resultData: Record<string, any>;
  riskScore: number;
  riskLevel: RiskLevel;
  createdAt: string;
}

export interface Assessment {
  id: string;
  organizationId: string;
  agentId: string;
  status: AssessmentStatus;
  startTime: string;
  endTime: string | null;
  metadata: Record<string, any>;
  overallRiskScore: number | null;
  createdAt: string;
  updatedAt: string;
  agent?: {
    id: string;
    hostname: string;
    status: string;
    version?: string;
  };
  results?: AssessmentResult[];
  reports?: {
    id: string;
    title: string;
    createdAt: string;
  }[];
  _count?: {
    results: number;
  };
}

export interface AssessmentStats {
  totalAssessments: number;
  recentAssessments: number;
  averageRiskScore: number;
  statusCounts: Record<string, number>;
}

export interface CreateAssessmentRequest {
  agentId: string;
  modules: CheckType[];
  metadata?: Record<string, any>;
}

export interface EnqueueJobsRequest {
  agentIds: string[];
  modules: CheckType[];
  options?: Record<string, any>;
}

export interface SubmitResultsRequest {
  results: {
    checkType: CheckType;
    resultData: Record<string, any>;
    riskScore: number;
    riskLevel: RiskLevel;
  }[];
  overallRiskScore?: number;
}

export interface GetAssessmentsParams {
  status?: AssessmentStatus;
  agentId?: string;
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export const assessmentApi = {
  /**
   * Create a new assessment
   */
  create: async (data: CreateAssessmentRequest): Promise<Assessment> => {
    try {
      const response = await apiClient.post('/assessments', data);
      return handleApiResponse<{ assessment: Assessment }>(response).assessment;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get all assessments for the organization
   */
  getAssessments: async (params: GetAssessmentsParams = {}): Promise<{
    assessments: Assessment[];
    pagination: {
      total: number;
      limit: number;
      offset: number;
      hasMore: boolean;
    };
  }> => {
    try {
      const queryParams = new URLSearchParams();
      if (params.status) queryParams.append('status', params.status);
      if (params.agentId) queryParams.append('agentId', params.agentId);
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());
      if (params.sortBy) queryParams.append('sortBy', params.sortBy);
      if (params.sortOrder) queryParams.append('sortOrder', params.sortOrder);

      const response = await apiClient.get(`/assessments?${queryParams.toString()}`);
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get specific assessment details
   */
  getAssessment: async (assessmentId: string): Promise<Assessment> => {
    try {
      const response = await apiClient.get(`/assessments/${assessmentId}`);
      return handleApiResponse<{ assessment: Assessment }>(response).assessment;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Submit assessment results (used by agents)
   */
  submitResults: async (assessmentId: string, data: SubmitResultsRequest): Promise<Assessment> => {
    try {
      const response = await apiClient.put(`/assessments/${assessmentId}/results`, data);
      return handleApiResponse<{ assessment: Assessment }>(response).assessment;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Stop a running assessment
   */
  stop: async (assessmentId: string): Promise<Assessment> => {
    try {
      const response = await apiClient.post(`/assessments/${assessmentId}/stop`);
      return handleApiResponse<{ assessment: Assessment }>(response).assessment;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Delete an assessment
   */
  delete: async (assessmentId: string): Promise<void> => {
    try {
      await apiClient.delete(`/assessments/${assessmentId}`);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Enqueue jobs for an assessment
   */
  enqueueJobs: async (assessmentId: string, data: EnqueueJobsRequest): Promise<void> => {
    try {
      await apiClient.post(`/assessments/${assessmentId}/enqueue`, data);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get assessment statistics
   */
  getStats: async (): Promise<AssessmentStats> => {
    try {
      const response = await apiClient.get('/assessments/stats');
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },
};