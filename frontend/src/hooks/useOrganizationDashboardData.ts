import { useEffect, useState } from 'react';
import { agentApi, AgentStats } from '@/services/agentApi';
import { assessmentApi, Assessment, AssessmentStats } from '@/services/assessmentApi';

interface OrganizationDashboardData {
  agentStats: AgentStats | null;
  assessmentStats: AssessmentStats | null;
  recentAssessments: Assessment[];
  isLoading: boolean;
  error: string | null;
  refetch: (organizationId?: string) => Promise<void>;
}

export function useOrganizationDashboardData(initialOrgId?: string): OrganizationDashboardData {
  const [agentStats, setAgentStats] = useState<AgentStats | null>(null);
  const [assessmentStats, setAssessmentStats] = useState<AssessmentStats | null>(null);
  const [recentAssessments, setRecentAssessments] = useState<Assessment[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = async (organizationId?: string) => {
    try {
      setIsLoading(true);
      setError(null);

      // Fetch all dashboard data in parallel
      const [agentStatsData, assessmentStatsData, recentAssessmentsData] = await Promise.all([
        agentApi.getStats(), // Agent stats typically remain user-scoped
        assessmentApi.getStats(organizationId), // Organization-specific assessment stats
        assessmentApi.getAssessments({
          limit: 10,
          sortBy: 'createdAt',
          sortOrder: 'desc',
        }),
      ]);

      setAgentStats(agentStatsData);
      setAssessmentStats(assessmentStatsData);
      setRecentAssessments(recentAssessmentsData.assessments);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
      console.error('Dashboard data fetch error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData(initialOrgId);
  }, [initialOrgId]);

  return {
    agentStats,
    assessmentStats,
    recentAssessments,
    isLoading,
    error,
    refetch: fetchDashboardData,
  };
}