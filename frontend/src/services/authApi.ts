import axios from 'axios';
import { AuthTokens, LoginRequest, LoginResponse, RegisterRequest } from '@/types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// Create axios instance
const api = axios.create({
  baseURL: `${API_BASE_URL}/api/auth`,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    // Get token from localStorage (or you could get from Zustand store)
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

// Response interceptor to handle token refresh
api.interceptors.response.use(
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
              const newTokens = await authApi.refreshToken(state.tokens.refreshToken);

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
              return api(originalRequest);
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

export const authApi = {
  /**
   * Login user
   */
  login: async (credentials: LoginRequest): Promise<LoginResponse> => {
    try {
      const response = await api.post('/login', credentials);
      return response.data.data;
    } catch (error: any) {
      const message = error.response?.data?.message || 'Login failed';
      throw new Error(message);
    }
  },

  /**
   * Register new user
   */
  register: async (data: RegisterRequest): Promise<LoginResponse> => {
    try {
      const response = await api.post('/register', data);
      return response.data.data;
    } catch (error: any) {
      const message = error.response?.data?.message || 'Registration failed';
      throw new Error(message);
    }
  },

  /**
   * Refresh access token
   */
  refreshToken: async (refreshToken: string): Promise<AuthTokens> => {
    try {
      const response = await api.post('/refresh', { refreshToken });
      return response.data.data.tokens;
    } catch (error: any) {
      const message = error.response?.data?.message || 'Token refresh failed';
      throw new Error(message);
    }
  },

  /**
   * Logout user
   */
  logout: async (): Promise<void> => {
    try {
      await api.post('/logout');
    } catch (error: any) {
      // Don't throw error for logout, just log it
      console.error('Logout API error:', error);
    }
  },

  /**
   * Get current user profile
   */
  getProfile: async () => {
    try {
      const response = await api.get('/profile');
      return response.data.data.user;
    } catch (error: any) {
      const message = error.response?.data?.message || 'Failed to get profile';
      throw new Error(message);
    }
  },

  /**
   * Change password
   */
  changePassword: async (currentPassword: string, newPassword: string): Promise<void> => {
    try {
      await api.put('/change-password', {
        currentPassword,
        newPassword,
      });
    } catch (error: any) {
      const message = error.response?.data?.message || 'Failed to change password';
      throw new Error(message);
    }
  },
};