import { Router } from 'express';
import { isJobsApiEnabled } from '@/config/featureFlags';
import { requireAgentJwt } from '@/middleware/agentAuth';
import { ackJob, startJob, submitJobResults, signArtifactUpload } from '@/controllers/jobController';

const router = Router();

if (isJobsApiEnabled()) {
  router.post('/:jobId/ack', requireAgentJwt, ackJob);
  router.post('/:jobId/start', requireAgentJwt, startJob);
  router.put('/:jobId/results', requireAgentJwt, submitJobResults);
  router.post('/:jobId/artifacts/sign-put', requireAgentJwt, signArtifactUpload);
}

export default router;
