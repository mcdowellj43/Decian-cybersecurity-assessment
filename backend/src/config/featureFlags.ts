export const featureFlags = {
  jobsApiEnabled: (process.env.JOBS_API_ENABLED || '').toLowerCase() === 'true',
};

export const isJobsApiEnabled = (): boolean => featureFlags.jobsApiEnabled;

export const refreshFeatureFlags = () => {
  featureFlags.jobsApiEnabled = (process.env.JOBS_API_ENABLED || '').toLowerCase() === 'true';
};
