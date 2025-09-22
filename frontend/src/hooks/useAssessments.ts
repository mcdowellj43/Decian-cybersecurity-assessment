import { useEffect, useState } from 'react';
import { assessmentApi, Assessment, GetAssessmentsParams } from '@/services/assessmentApi';

interface UseAssessmentsResult {
  assessments: Assessment[];
  totalAssessments: number;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  loadMore: () => Promise<void>;
  hasMore: boolean;
}

export function useAssessments(params: GetAssessmentsParams = {}): UseAssessmentsResult {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [totalAssessments, setTotalAssessments] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [currentOffset, setCurrentOffset] = useState(0);

  const limit = params.limit || 20;

  const fetchAssessments = async (offset = 0, append = false) => {
    try {
      if (!append) {
        setIsLoading(true);
      }
      setError(null);

      const response = await assessmentApi.getAssessments({
        ...params,
        limit,
        offset,
      });

      if (append) {
        setAssessments(prev => [...prev, ...response.assessments]);
      } else {
        setAssessments(response.assessments);
      }

      setTotalAssessments(response.pagination.total);
      setHasMore(response.pagination.hasMore);
      setCurrentOffset(offset);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load assessments');
      console.error('Assessments fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const refetch = async () => {
    await fetchAssessments(0, false);
  };

  const loadMore = async () => {
    if (hasMore && !isLoading) {
      await fetchAssessments(currentOffset + limit, true);
    }
  };

  useEffect(() => {
    fetchAssessments();
  }, [params.status, params.agentId]); // Refetch when filters change

  return {
    assessments,
    totalAssessments,
    isLoading,
    error,
    refetch,
    loadMore,
    hasMore,
  };
}