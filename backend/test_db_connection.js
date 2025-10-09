const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function testDatabase() {
  try {
    console.log('=== Database Connection Test ===');

    // Test database connection
    await prisma.$connect();
    console.log('✅ Database connected successfully');

    // Get database info
    const dbInfo = await prisma.$queryRaw`SELECT sqlite_version() as version`;
    console.log('📊 Database type: SQLite');
    console.log('📊 SQLite version:', dbInfo[0].version);

    // Check all tables
    const tables = await prisma.$queryRaw`
      SELECT name FROM sqlite_master
      WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_prisma%'
      ORDER BY name
    `;
    console.log('\n📋 Available tables:', tables.map(t => t.name));

    // Count records in key tables
    const assessmentCount = await prisma.assessment.count();
    const assessmentResultCount = await prisma.assessmentResult.count();
    const jobResultCount = await prisma.jobResult.count();

    console.log('\n📊 Record counts:');
    console.log('  Assessments:', assessmentCount);
    console.log('  AssessmentResults:', assessmentResultCount);
    console.log('  JobResults:', jobResultCount);

    // Show sample AssessmentResult if any exist
    if (assessmentResultCount > 0) {
      const sampleResult = await prisma.assessmentResult.findFirst({
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

      console.log('\n🔍 Sample AssessmentResult:');
      console.log('  ID:', sampleResult.id);
      console.log('  Assessment ID:', sampleResult.assessmentId);
      console.log('  Check Type:', sampleResult.checkType);
      console.log('  Risk Score:', sampleResult.riskScore);
      console.log('  Risk Level:', sampleResult.riskLevel);
      console.log('  Result Data type:', typeof sampleResult.resultData);
      console.log('  Assessment Status:', sampleResult.assessment.status);
    }

    // Show sample JobResult if any exist
    if (jobResultCount > 0) {
      const sampleJobResult = await prisma.jobResult.findFirst();
      console.log('\n🔍 Sample JobResult:');
      console.log('  ID:', sampleJobResult.id);
      console.log('  Status:', sampleJobResult.status);
      console.log('  Summary type:', typeof sampleJobResult.summary);
    }

  } catch (error) {
    console.error('❌ Database test failed:', error.message);
    if (error.code) {
      console.error('Error code:', error.code);
    }
  } finally {
    await prisma.$disconnect();
  }
}

testDatabase();