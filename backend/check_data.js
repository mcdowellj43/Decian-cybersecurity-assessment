const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function checkData() {
  try {
    // Check AssessmentResult data
    const assessmentResults = await prisma.assessmentResult.findMany({
      take: 10,
      include: {
        assessment: {
          select: {
            id: true,
            status: true,
            organizationId: true
          }
        }
      }
    });

    console.log('AssessmentResult count:', assessmentResults.length);

    if (assessmentResults.length > 0) {
      console.log('Sample AssessmentResult:');
      console.log('ID:', assessmentResults[0].id);
      console.log('Assessment ID:', assessmentResults[0].assessmentId);
      console.log('Check Type:', assessmentResults[0].checkType);
      console.log('Risk Score:', assessmentResults[0].riskScore);
      console.log('Assessment Status:', assessmentResults[0].assessment.status);

      // Check if assessment has results relation working
      const assessmentWithResults = await prisma.assessment.findFirst({
        where: { id: assessmentResults[0].assessmentId },
        include: {
          results: true,
          agent: { select: { hostname: true } },
          organization: { select: { name: true } }
        }
      });

      console.log('\nAssessment with results:');
      console.log('Assessment ID:', assessmentWithResults?.id);
      console.log('Results count via relation:', assessmentWithResults?.results?.length || 0);
      console.log('Assessment status:', assessmentWithResults?.status);
    }

  } catch (error) {
    console.error('Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

checkData();