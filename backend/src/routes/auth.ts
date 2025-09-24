import { Router } from 'express';
import {
  register,
  login,
  refreshToken,
  getProfile,
  changePassword,
  logout
} from '@/controllers/authController';
import { authenticate } from '@/middleware/auth';
import { validateSchema, registerSchema, loginSchema, refreshTokenSchema, changePasswordSchema } from '@/utils/validation';

const router = Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user and organization
 * @access  Public
 */
router.post('/register', validateSchema(registerSchema), register);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', validateSchema(loginSchema), login);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token
 * @access  Public
 */
router.post('/refresh', validateSchema(refreshTokenSchema), refreshToken);

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', authenticate, getProfile);

/**
 * @route   PUT /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.put('/change-password', authenticate, validateSchema(changePasswordSchema), changePassword);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Private
 */
router.post('/logout', authenticate, logout);

export default router;