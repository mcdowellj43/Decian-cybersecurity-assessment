import { useEffect, useState } from 'react';
import { agentApi, Agent, GetAgentsParams } from '@/services/agentApi';

interface UseAgentsResult {
  agents: Agent[];
  totalAgents: number;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  loadMore: () => Promise<void>;
  hasMore: boolean;
}

export function useAgents(params: GetAgentsParams = {}): UseAgentsResult {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [totalAgents, setTotalAgents] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [currentOffset, setCurrentOffset] = useState(0);

  const limit = params.limit || 20;

  const fetchAgents = async (offset = 0, append = false) => {
    try {
      if (!append) {
        setIsLoading(true);
      }
      setError(null);

      const response = await agentApi.getAgents({
        ...params,
        limit,
        offset,
      });

      if (append) {
        setAgents(prev => [...prev, ...response.agents]);
      } else {
        setAgents(response.agents);
      }

      setTotalAgents(response.pagination.total);
      setHasMore(response.pagination.hasMore);
      setCurrentOffset(offset);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents');
      console.error('Agents fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const refetch = async () => {
    await fetchAgents(0, false);
  };

  const loadMore = async () => {
    if (hasMore && !isLoading) {
      await fetchAgents(currentOffset + limit, true);
    }
  };

  useEffect(() => {
    fetchAgents();
  }, [params.status]); // Refetch when status filter changes

  return {
    agents,
    totalAgents,
    isLoading,
    error,
    refetch,
    loadMore,
    hasMore,
  };
}