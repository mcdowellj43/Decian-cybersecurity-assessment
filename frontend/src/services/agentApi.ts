import { apiClient, handleApiResponse, handleApiError } from './apiClient';

export interface Agent {
  id: string;
  hostname: string;
  version: string;
  status: 'ONLINE' | 'OFFLINE' | 'ERROR';
  configuration: Record<string, any>;
  lastSeen: string | null;
  createdAt: string;
  updatedAt: string;
  assessments?: Assessment[];
}

export interface Assessment {
  id: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  createdAt: string;
}

export interface AgentStats {
  totalAgents: number;
  recentlyActive: number;
  statusCounts: Record<string, number>;
}

export interface CreateAgentRequest {
  hostname: string;
  version: string;
  configuration?: Record<string, any>;
}

export interface UpdateAgentRequest {
  configuration?: Record<string, any>;
  status?: 'ONLINE' | 'OFFLINE' | 'ERROR';
}

export interface HeartbeatRequest {
  status?: 'ONLINE' | 'OFFLINE' | 'ERROR';
  metadata?: Record<string, any>;
}

export interface GetAgentsParams {
  status?: string;
  limit?: number;
  offset?: number;
}

export interface AgentDownloadResponse {
  config: string;
  instructions: string;
  downloadUrl: string | null;
  buildRequired: boolean;
  organizationId?: string;
  agentFileName?: string;
  sourceRepository?: string;
}

export const agentApi = {
  /**
   * Register a new agent
   */
  register: async (data: CreateAgentRequest): Promise<Agent> => {
    try {
      const response = await apiClient.post('/agents/register', data);
      return handleApiResponse<{ agent: Agent }>(response).agent;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get all agents for the organization
   */
  getAgents: async (params: GetAgentsParams = {}): Promise<{
    agents: Agent[];
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
      if (params.limit) queryParams.append('limit', params.limit.toString());
      if (params.offset) queryParams.append('offset', params.offset.toString());

      const response = await apiClient.get(`/agents?${queryParams.toString()}`);
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get specific agent details
   */
  getAgent: async (agentId: string): Promise<Agent> => {
    try {
      const response = await apiClient.get(`/agents/${agentId}`);
      return handleApiResponse<{ agent: Agent }>(response).agent;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Update agent configuration
   */
  updateAgent: async (agentId: string, data: UpdateAgentRequest): Promise<Agent> => {
    try {
      const response = await apiClient.put(`/agents/${agentId}`, data);
      return handleApiResponse<{ agent: Agent }>(response).agent;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Delete agent
   */
  deleteAgent: async (agentId: string): Promise<void> => {
    try {
      await apiClient.delete(`/agents/${agentId}`);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Send agent heartbeat
   */
  sendHeartbeat: async (agentId: string, data: HeartbeatRequest): Promise<Agent> => {
    try {
      const response = await apiClient.post(`/agents/${agentId}/heartbeat`, data);
      return handleApiResponse<{ agent: Agent }>(response).agent;
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Get agent statistics
   */
  getStats: async (): Promise<AgentStats> => {
    try {
      const response = await apiClient.get('/agents/stats');
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Download agent executable or get setup instructions
   */
  download: async (): Promise<AgentDownloadResponse> => {
    try {
      const response = await apiClient.get('/agents/download');
      return handleApiResponse(response);
    } catch (error) {
      throw handleApiError(error);
    }
  },

  /**
   * Download agent executable as file (for direct file downloads)
   */
  downloadFile: async (): Promise<void> => {
    try {
      const response = await apiClient.get('/agents/download', {
        responseType: 'blob',
      });

      // Check if response contains a blob (actual file)
      if (response.data instanceof Blob) {
        const url = window.URL.createObjectURL(response.data);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'decian-agent.exe';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } else {
        // If not a blob, it's probably JSON with instructions
        throw new Error('Agent executable not available. Please check the download instructions.');
      }
    } catch (error) {
      throw handleApiError(error);
    }
  },
};