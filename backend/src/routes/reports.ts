import { Router } from 'express';
import { authenticate, requireRole } from '@/middleware/auth';
import {
  generateReport,
  getReports,
  getReportById,
  deleteReport,
} from '@/controllers/reportController';
import { UserRole } from '@prisma/client';

const router = Router();

// All report routes require authentication
router.use(authenticate);

/**
 * @route   POST /api/reports/generate
 * @desc    Generate HTML report from assessment
 * @access  Private (USER+)
 */
router.post('/generate', requireRole(UserRole.USER), generateReport);

/**
 * @route   GET /api/reports
 * @desc    Get available reports for organization
 * @access  Private (VIEWER+)
 */
router.get('/', getReports);

/**
 * @route   GET /api/reports/:id
 * @desc    Download specific report (HTML or JSON)
 * @access  Private (VIEWER+)
 */
router.get('/:id', getReportById);

/**
 * @route   DELETE /api/reports/:id
 * @desc    Delete a report
 * @access  Private (ADMIN)
 */
router.delete('/:id', requireRole(UserRole.ADMIN), deleteReport);

export default router;