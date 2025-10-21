import express from 'express';
import { UserRole } from '@prisma/client';
import { validateSchema, createOrganizationSchema, updateOrganizationSchema } from '@/utils/validation';
import { authenticate, requireRole } from '@/middleware/auth';
import {
  getOrganizations,
  getOrganization,
  createOrganization,
  updateOrganization,
  deleteOrganization,
  getEnrollmentToken,
  regenerateEnrollmentToken,
  getEnrollmentTokenHistory,
} from '@/controllers/organizationController';

const router = express.Router();

// Apply authentication to all routes
router.use(authenticate);

/**
 * @route   GET /api/organizations
 * @desc    Get all organizations (admin only)
 * @access  Private (Admin)
 */
router.get('/', requireRole(UserRole.ADMIN), getOrganizations);

/**
 * @route   POST /api/organizations
 * @desc    Create new organization (admin only)
 * @access  Private (Admin)
 */
router.post(
  '/',
  requireRole(UserRole.ADMIN),
  validateSchema(createOrganizationSchema),
  createOrganization
);

/**
 * @route   GET /api/organizations/:id
 * @desc    Get single organization
 * @access  Private (Own org or Admin)
 */
router.get('/:id', getOrganization);

/**
 * @route   PUT /api/organizations/:id
 * @desc    Update organization
 * @access  Private (Own org or Admin)
 */
router.put(
  '/:id',
  validateSchema(updateOrganizationSchema),
  updateOrganization
);

/**
 * @route   DELETE /api/organizations/:id
 * @desc    Delete organization (admin only)
 * @access  Private (Admin)
 */
router.delete(
  '/:id',
  requireRole(UserRole.ADMIN),
  deleteOrganization
);

/**
 * @route   GET /api/organizations/:id/enrollment-token
 * @desc    Get current enrollment token for organization
 * @access  Private (Own org or Admin)
 */
router.get('/:id/enrollment-token', getEnrollmentToken);

/**
 * @route   POST /api/organizations/:id/enrollment-token/regenerate
 * @desc    Generate new enrollment token for organization
 * @access  Private (Own org or Admin)
 */
router.post('/:id/enrollment-token/regenerate', regenerateEnrollmentToken);

/**
 * @route   GET /api/organizations/:id/enrollment-token/history
 * @desc    Get enrollment token history for organization
 * @access  Private (Own org or Admin)
 */
router.get('/:id/enrollment-token/history', getEnrollmentTokenHistory);

export default router;