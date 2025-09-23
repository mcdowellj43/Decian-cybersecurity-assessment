import { useEffect, useState } from 'react';
import { assessmentApi, Assessment, GetAssessmentsParams, CreateAssessmentRequest } from '@/services/assessmentApi';

interface UseAssessmentsResult {
  assessments: Assessment[];
  totalAssessments: number;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  loadMore: () => Promise<void>;
  hasMore: boolean;
  createAssessment: (data: CreateAssessmentRequest) => Promise<void>;
  deleteAssessment: (id: string) => Promise<void>;
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

  const createAssessment = async (data: CreateAssessmentRequest) => {
    try {
      setError(null);
      await assessmentApi.create(data);
      await refetch(); // Refresh the list after creating
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create assessment');
      throw err;
    }
  };

  const deleteAssessment = async (id: string) => {
    try {
      setError(null);
      await assessmentApi.delete(id);
      await refetch(); // Refresh the list after deleting
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete assessment');
      throw err;
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
    createAssessment,
    deleteAssessment,
  };
}