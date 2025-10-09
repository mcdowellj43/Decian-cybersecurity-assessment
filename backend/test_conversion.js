const { PrismaClient, JobStatus, AssessmentStatus } = require('@prisma/client');

const prisma = new PrismaClient();

// Copy the maybeUpdateAssessment logic to test it
async function testMaybeUpdateAssessment(jobId) {
  const job = await prisma.job.findUnique({
    where: { id: jobId },
    include: { result: true }
  });

  if (!job) {
    console.log('Job not found');
    return;
  }

  console.log('=== JOB DATA ===');
  console.log('Job ID:', job.id);
  console.log('Job Status:', job.status);
  console.log('Job Result Status:', job.result?.status);

  if (typeof job.payload !== 'object' || job.payload === null) {
    console.log('Invalid payload');
    return;
  }

  const payload = job.payload;
  if (typeof payload.assessmentId !== 'string') {
    console.log('No assessmentId in payload');
    return;
  }

  const assessmentId = payload.assessmentId;
  console.log('Assessment ID:', assessmentId);

  // Get job result
  const jobResult = await prisma.jobResult.findUnique({
    where: { jobId: job.id },
  });

  if (!jobResult || !jobResult.summary) {
    console.log('No job result or summary');
    return;
  }

  const summary = jobResult.summary;
  console.log('\n=== SUMMARY ANALYSIS ===');
  console.log('Has results:', !!(summary.results));
  console.log('Has targets:', !!(summary.targets));

  // Extract results using the new logic
  let allResults = [];

  // Check if results are in the new format (targets[].results)
  if (summary.targets && Array.isArray(summary.targets)) {
    for (const target of summary.targets) {
      if (target.results && Array.isArray(target.results)) {
        allResults = allResults.concat(target.results);
      }
    }
  }

  // Fallback to old format (summary.results)
  if (allResults.length === 0 && summary.results && Array.isArray(summary.results)) {
    allResults = summary.results;
  }

  console.log('Extracted results count:', allResults.length);

  if (allResults.length > 0) {
    console.log('\n=== ASSESSMENT RESULTS TO CREATE ===');
    const assessmentResults = allResults.map((result) => ({
      assessmentId,
      checkType: result.checkType,
      resultData: JSON.stringify(result.data || {}),
      riskScore: result.riskScore || 0,
      riskLevel: result.riskLevel || 'LOW',
    }));

    console.log('Results to create:', assessmentResults.map(r => ({
      checkType: r.checkType,
      riskScore: r.riskScore,
      riskLevel: r.riskLevel
    })));

    try {
      // Create the assessment results
      const created = await prisma.assessmentResult.createMany({
        data: assessmentResults,
      });

      console.log('\n✅ SUCCESS: Created', created.count, 'assessment results');

      // Update assessment status
      await prisma.assessment.updateMany({
        where: { id: assessmentId },
        data: {
          status: AssessmentStatus.COMPLETED,
          endTime: new Date(),
          overallRiskScore: summary.overallRiskScore || 0,
        },
      });

      console.log('✅ Updated assessment status to COMPLETED');

    } catch (error) {
      console.error('❌ Error creating assessment results:', error.message);
    }
  } else {
    console.log('❌ No results to create');
  }
}

async function main() {
  try {
    // Get the most recent successful job
    const jobResult = await prisma.jobResult.findFirst({
      where: { status: 'SUCCEEDED' },
      orderBy: { finishedAt: 'desc' },
      include: { job: true }
    });

    if (jobResult) {
      await testMaybeUpdateAssessment(jobResult.job.id);
    } else {
      console.log('No successful job found');
    }
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

main();