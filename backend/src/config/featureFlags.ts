const parseBooleanFlag = (value: string | undefined, defaultValue: boolean) => {
  if (value === undefined) {
    return defaultValue;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'true') {
    return true;
  }
  if (normalized === 'false') {
    return false;
  }

  return defaultValue;
};

export const featureFlags = {
  jobsApiEnabled: parseBooleanFlag(process.env.JOBS_API_ENABLED, true),
};

export const isJobsApiEnabled = (): boolean => featureFlags.jobsApiEnabled;

export const refreshFeatureFlags = () => {
  featureFlags.jobsApiEnabled = parseBooleanFlag(process.env.JOBS_API_ENABLED, true);
};
