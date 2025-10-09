const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function checkJobSummary() {
  try {
    // Get the most recent successful JobResult
    const jobResult = await prisma.jobResult.findFirst({
      where: { status: 'SUCCEEDED' },
      orderBy: { finishedAt: 'desc' },
      include: {
        job: {
          select: {
            id: true,
            payload: true
          }
        }
      }
    });

    if (jobResult) {
      console.log('=== JOB RESULT ANALYSIS ===');
      console.log('Job ID:', jobResult.jobId);
      console.log('Status:', jobResult.status);
      console.log('Summary type:', typeof jobResult.summary);
      console.log('\n=== SUMMARY STRUCTURE ===');
      console.log(JSON.stringify(jobResult.summary, null, 2));

      console.log('\n=== PAYLOAD STRUCTURE ===');
      console.log(JSON.stringify(jobResult.job.payload, null, 2));
    } else {
      console.log('No successful JobResult found');
    }

  } catch (error) {
    console.error('Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkJobSummary();