import { useEffect, useState } from 'react';
import { agentApi, Agent, AgentStats } from '@/services/agentApi';
import { assessmentApi, Assessment, AssessmentStats } from '@/services/assessmentApi';

interface DashboardData {
  agentStats: AgentStats | null;
  assessmentStats: AssessmentStats | null;
  recentAssessments: Assessment[];
  isLoading: boolean;
  error: string | null;
}

export function useDashboardData(): DashboardData {
  const [agentStats, setAgentStats] = useState<AgentStats | null>(null);
  const [assessmentStats, setAssessmentStats] = useState<AssessmentStats | null>(null);
  const [recentAssessments, setRecentAssessments] = useState<Assessment[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setIsLoading(true);
        setError(null);

        // Fetch all dashboard data in parallel
        const [agentStatsData, assessmentStatsData, recentAssessmentsData] = await Promise.all([
          agentApi.getStats(),
          assessmentApi.getStats(),
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

    fetchDashboardData();
  }, []);

  return {
    agentStats,
    assessmentStats,
    recentAssessments,
    isLoading,
    error,
  };
}