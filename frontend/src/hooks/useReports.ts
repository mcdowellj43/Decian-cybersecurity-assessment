import { useState, useEffect } from 'react';
import { reportApi, Report, GetReportsParams } from '@/services/reportApi';

export interface UseReportsReturn {
  reports: Report[];
  isLoading: boolean;
  error: string | null;
  refetch: () => void;
  downloadHTML: (reportId: string) => Promise<void>;
}

export function useReports(params: GetReportsParams = {}): UseReportsReturn {
  const [reports, setReports] = useState<Report[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const response = await reportApi.getReports(params);
      setReports(response.reports);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch reports');
    } finally {
      setIsLoading(false);
    }
  };

  const downloadHTML = async (reportId: string) => {
    try {
      const htmlContent = await reportApi.downloadHTML(reportId);

      // Create blob and download
      const blob = new Blob([htmlContent], { type: 'text/html' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `report-${reportId}.html`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Failed to download report');
    }
  };

  useEffect(() => {
    fetchReports();
  }, [params.assessmentId, params.limit, params.offset]);

  return {
    reports,
    isLoading,
    error,
    refetch: fetchReports,
    downloadHTML,
  };
}