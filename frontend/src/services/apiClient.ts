import axios from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// Create base axios instance
export const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    if (typeof window !== 'undefined') {
      const authStorage = localStorage.getItem('auth-storage');
      if (authStorage) {
        try {
          const { state } = JSON.parse(authStorage);
          if (state?.tokens?.accessToken) {
            config.headers.Authorization = `Bearer ${state.tokens.accessToken}`;
          }
        } catch (error) {
          console.error('Error parsing auth storage:', error);
        }
      }
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors and token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Get refresh token from storage
        if (typeof window !== 'undefined') {
          const authStorage = localStorage.getItem('auth-storage');
          if (authStorage) {
            const { state } = JSON.parse(authStorage);
            if (state?.tokens?.refreshToken) {
              // Try to refresh token
              const refreshResponse = await axios.post(
                `${API_BASE_URL}/api/auth/refresh`,
                { refreshToken: state.tokens.refreshToken }
              );

              const newTokens = refreshResponse.data.data.tokens;

              // Update storage with new tokens
              const updatedStorage = {
                ...JSON.parse(authStorage),
                state: {
                  ...state,
                  tokens: newTokens,
                },
              };
              localStorage.setItem('auth-storage', JSON.stringify(updatedStorage));

              // Retry original request with new token
              originalRequest.headers.Authorization = `Bearer ${newTokens.accessToken}`;
              return apiClient(originalRequest);
            }
          }
        }
      } catch (refreshError) {
        // Refresh failed, redirect to login
        if (typeof window !== 'undefined') {
          localStorage.removeItem('auth-storage');
          window.location.href = '/login';
        }
      }
    }

    return Promise.reject(error);
  }
);

// Helper function to handle API responses
export const handleApiResponse = <T>(response: any): T => {
  if (response.data.status === 'success') {
    return response.data.data;
  } else {
    throw new Error(response.data.message || 'API request failed');
  }
};

// Helper function to handle API errors
export const handleApiError = (error: any): Error => {
  if (error.response?.data?.message) {
    return new Error(error.response.data.message);
  } else if (error.message) {
    return new Error(error.message);
  } else {
    return new Error('An unexpected error occurred');
  }
};