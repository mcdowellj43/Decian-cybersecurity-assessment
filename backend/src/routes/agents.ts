import { Router } from 'express';
import { authenticate, requireRole } from '@/middleware/auth';
import {
  registerAgent,
  mintAgentToken,
  getAgents,
  getAgentById,
  updateAgent,
  deleteAgent,
  agentHeartbeat,
  getAgentStats,
  downloadAgent,
  getAgentModules,
} from '@/controllers/agentController';
import { nextJobs } from '@/controllers/jobController';
import { UserRole } from '@prisma/client';
import { isJobsApiEnabled } from '@/config/featureFlags';
import { requireAgentJwt } from '@/middleware/agentAuth';

const router = Router();

/**
 * @route   POST /api/agents/register
 * @desc    Agent self-registration (unauthenticated)
 * @access  Public (Agents with embedded organization ID)
 */
router.post('/register', registerAgent);

if (isJobsApiEnabled()) {
  router.post('/:id/tokens', mintAgentToken);
  router.get('/:id/next-jobs', requireAgentJwt, nextJobs);
}

// All other agent routes require authentication
router.use(authenticate);

/**
 * @route   GET /api/agents/download
 * @desc    Download agent executable with configuration
 * @access  Private (USER+)
 */
router.get('/download', requireRole(UserRole.USER), downloadAgent);


/**
 * @route   GET /api/agents/stats
 * @desc    Get agent statistics for organization
 * @access  Private (VIEWER+)
 */
router.get('/stats', getAgentStats);

/**
 * @route   GET /api/agents
 * @desc    Get all agents for organization
 * @access  Private (VIEWER+)
 */
router.get('/', getAgents);

/**
 * @route   GET /api/agents/:id
 * @desc    Get specific agent details
 * @access  Private (VIEWER+)
 */
router.get('/:id', getAgentById);

/**
 * @route   GET /api/agents/:id/modules
 * @desc    Get available modules from specific agent
 * @access  Private (VIEWER+)
 */
router.get('/:id/modules', getAgentModules);

/**
 * @route   PUT /api/agents/:id
 * @desc    Update agent configuration
 * @access  Private (USER+)
 */
router.put('/:id', requireRole(UserRole.USER), updateAgent);

/**
 * @route   DELETE /api/agents/:id
 * @desc    Delete agent
 * @access  Private (ADMIN)
 */
router.delete('/:id', requireRole(UserRole.ADMIN), deleteAgent);

/**
 * @route   POST /api/agents/:id/heartbeat
 * @desc    Agent heartbeat to update status
 * @access  Private (USER+) - Agents will use API keys
 */
router.post('/:id/heartbeat', requireRole(UserRole.USER), agentHeartbeat);

export default router;