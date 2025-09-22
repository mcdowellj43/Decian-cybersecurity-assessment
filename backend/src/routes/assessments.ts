import { Router } from 'express';
import { authenticate, requireRole } from '@/middleware/auth';
import {
  createAssessment,
  getAssessments,
  getAssessmentById,
  submitAssessmentResults,
  stopAssessment,
  deleteAssessment,
  getAssessmentStats,
} from '@/controllers/assessmentController';
import { UserRole } from '@prisma/client';

const router = Router();

// All assessment routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/assessments/stats
 * @desc    Get assessment statistics for organization
 * @access  Private (VIEWER+)
 */
router.get('/stats', getAssessmentStats);

/**
 * @route   POST /api/assessments
 * @desc    Create a new assessment
 * @access  Private (USER+)
 */
router.post('/', requireRole(UserRole.USER), createAssessment);

/**
 * @route   GET /api/assessments
 * @desc    Get all assessments for organization
 * @access  Private (VIEWER+)
 */
router.get('/', getAssessments);

/**
 * @route   GET /api/assessments/:id
 * @desc    Get specific assessment details
 * @access  Private (VIEWER+)
 */
router.get('/:id', getAssessmentById);

/**
 * @route   PUT /api/assessments/:id/results
 * @desc    Submit assessment results from agent
 * @access  Private (USER+) - Agents will use API keys
 */
router.put('/:id/results', requireRole(UserRole.USER), submitAssessmentResults);

/**
 * @route   POST /api/assessments/:id/stop
 * @desc    Stop a running assessment
 * @access  Private (USER+)
 */
router.post('/:id/stop', requireRole(UserRole.USER), stopAssessment);

/**
 * @route   DELETE /api/assessments/:id
 * @desc    Delete assessment and its results
 * @access  Private (ADMIN)
 */
router.delete('/:id', requireRole(UserRole.ADMIN), deleteAssessment);

export default router;