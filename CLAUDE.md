# CLAUDE.md - Cybersecurity Risk Assessment Platform

## PROJECT OVERVIEW

This is a comprehensive cybersecurity risk assessment platform consisting of a centralized web dashboard and distributed Go-based agents. The platform performs automated security assessments across Windows environments and provides executive-level reporting with actionable insights.

### 📋 QUICK STATUS SUMMARY
- **PHASE**: 1 of 3 (Core Platform Development)
- **PROGRESS**: 60% Complete (Authentication & Foundation ✅, API Layer 🔄, Agent Framework ⏳)
- **NEXT MILESTONE**: Working end-to-end assessment flow (3 weeks)
- **CURRENT FOCUS**: Core API endpoints for agent/assessment management

### Core Architecture Status
- **Frontend Dashboard**: Next.js 15.5.3 with TypeScript ✅ **COMPLETE**
- **Backend API**: Node.js/Express with TypeScript ✅ **COMPLETE**
- **Authentication System**: JWT with role-based access ✅ **COMPLETE**
- **Database Layer**: PostgreSQL with Prisma ORM ✅ **COMPLETE**
- **API Endpoints**: Agent/Assessment management 🔄 **IN PROGRESS**
- **Go Agents**: Windows assessment executables ⏳ **PENDING**
- **Communication**: Secure agent-to-dashboard protocol ⏳ **PENDING**

---

## IMPLEMENTATION STATUS

### ✅ COMPLETED FOUNDATION (100% Complete)

#### 1. Frontend Dashboard (Next.js 15.5.3)
- **✅ Core Setup**: Tailwind CSS with project-specific color scheme (#2563eb primary)
- **✅ Component Library**: Button, Card, RiskIndicator, Input components with TypeScript
- **✅ Layout System**: Sidebar, Header, AuthAwareLayout with navigation
- **✅ Authentication UI**: LoginForm, RegisterForm with React Hook Form + Zod validation
- **✅ State Management**: Zustand store for authentication with persistence
- **✅ Protected Routes**: ProtectedRoute component with role-based access control
- **✅ API Integration**: Complete authApi service with token refresh interceptors
- **✅ Dashboard Homepage**: Security metrics display with mock data
- **✅ Build System**: TypeScript, ESLint, successful production builds

#### 2. Backend API (Node.js/Express)
- **✅ Core Server**: Express with TypeScript, security middleware (helmet, CORS, rate limiting)
- **✅ Authentication System**: Complete JWT implementation with access/refresh tokens
- **✅ User Management**: Registration, login, logout, password change endpoints
- **✅ Security**: bcryptjs password hashing, role-based authorization middleware
- **✅ Validation**: Zod schemas for request validation with comprehensive error handling
- **✅ Logging**: Winston structured logging with file and console outputs
- **✅ Database Integration**: Prisma client with connection management
- **✅ Environment**: .env.example with all required configuration variables

#### 3. Database Layer (PostgreSQL + Prisma ORM)
- **✅ Schema Design**: Complete Prisma schema with Organizations, Users, Agents, Assessments
- **✅ User System**: User roles (ADMIN, USER, VIEWER) with organization relationships
- **✅ Assessment Models**: Assessment, AssessmentResult with 15 check types
- **✅ Agent Models**: Agent status tracking and configuration
- **✅ Report Models**: HTML report generation structure
- **✅ Audit System**: AuditLog model for security event tracking
- **✅ Enums**: CheckType, RiskLevel, AssessmentStatus, AgentStatus
- **✅ Client Generation**: Prisma client generated and integrated

### 🔄 CURRENT PHASE: CORE API DEVELOPMENT (0% Complete)

#### Required API Endpoints (Next Priority)
1. **Agent Management APIs** `/api/agents`
   - `POST /api/agents/register` - Agent registration with hostname validation
   - `GET /api/agents` - List organization agents with status
   - `GET /api/agents/:id` - Get agent details and configuration
   - `PUT /api/agents/:id` - Update agent configuration
   - `DELETE /api/agents/:id` - Remove agent
   - `POST /api/agents/:id/heartbeat` - Agent status updates

2. **Assessment Management APIs** `/api/assessments`
   - `POST /api/assessments` - Create new assessment with module selection
   - `GET /api/assessments` - List assessments with filtering/pagination
   - `GET /api/assessments/:id` - Get assessment details and results
   - `PUT /api/assessments/:id/results` - Agent result submission
   - `DELETE /api/assessments/:id` - Remove assessment
   - `POST /api/assessments/:id/stop` - Stop running assessment

3. **Report Generation APIs** `/api/reports`
   - `POST /api/reports/generate` - Generate HTML report from assessment
   - `GET /api/reports/:id` - Download generated report
   - `GET /api/reports` - List available reports

### ⏳ PENDING IMPLEMENTATION (Phase 1 Remaining)

#### Go Agent Framework (0% Complete)
**Target**: First working Windows assessment agent
- **CLI Application**: Go 1.21+ with cobra CLI framework
- **Configuration**: YAML config files for dashboard endpoint and modules
- **Communication**: HTTPS client for secure API communication
- **Module System**: Plugin architecture for assessment modules
- **First 5 Modules**:
  1. `win-update-check` - Windows Update status
  2. `win-firewall-status-check` - Firewall configuration
  3. `pshell-exec-policy-check` - PowerShell execution policy
  4. `accounts-bypass-pass-policy` - Password policy analysis
  5. `EOL-software-check` - End-of-life software detection

#### Dashboard Integration (0% Complete)
- **Real API Integration**: Replace mock data with live API calls
- **Agent Status Display**: Real-time agent monitoring
- **Assessment Creation**: UI for launching assessments
- **Results Visualization**: Live assessment results display
- **Error Handling**: Comprehensive error states and loading indicators

---

## FUNCTIONAL REQUIREMENTS

### 1. WEB DASHBOARD CAPABILITIES

#### Primary Features
- **Analytics Dashboard**: Real-time visualization of risk assessment data
- **Agent Management**: Download, deploy, and monitor assessment agents
- **Report Generation**: Create and download comprehensive HTML security reports
- **Data Visualization**: Charts, graphs, and metrics displaying security posture
- **Historical Tracking**: Trend analysis and comparison across multiple assessments

#### Dashboard Sections
1. **Overview Page**: High-level security metrics and recent assessment summary
2. **Assessments Page**: Detailed view of individual and comparative assessments
3. **Agents Page**: Agent download, status monitoring, and configuration
4. **Reports Page**: Generate, view, and download assessment reports
5. **Settings Page**: Platform configuration and user management

### 2. AGENT FUNCTIONALITY

#### Core Assessment Modules (Go Implementation Required)

**Minimum Requirements Checks:**
1. **Account Policy Analysis** (`accounts-bypass-pass-policy`)
   - Domain password policy enumeration
   - Lockout policy assessment
   - Fine-grained password policy detection
   - Policy compliance scoring

2. **Domain Controller Security** (`DC-open-ports-check`)
   - TCP port scanning and service enumeration
   - Critical DC service validation
   - Unexpected service detection
   - Port risk assessment

3. **DNS Security Assessment** (`DNS-config-check`)
   - DNS client/server configuration review
   - Cache poisoning vulnerability detection
   - Insecure DNS settings identification
   - DNS security recommendations

4. **End-of-Life Software Detection** (`EOL-software-check`)
   - Complete software inventory collection
   - EOL product identification using built-in dataset
   - Version tracking and support status
   - Risk scoring based on EOL timeline

5. **Inactive Account Analysis** (`enabled-inactive-accounts`)
   - AD user activity monitoring
   - Privileged account identification
   - Inactivity threshold configuration
   - Risk factor annotation

6. **Network Protocol Security** (`network-protocols-check`)
   - SMBv1/SMBv2 configuration assessment
   - Insecure service detection (Telnet/FTP/SNMP)
   - TLS/SSL protocol evaluation
   - Protocol hardening recommendations

7. **PowerShell Security** (`pshell-exec-policy-check`)
   - Execution policy enumeration
   - Logging configuration assessment
   - Script execution risk evaluation
   - PowerShell hardening guidance

8. **Service Account Privileges** (`service-accounts-domain-admin`)
   - Service account enumeration
   - High-privilege group membership detection
   - Service account risk assessment
   - Privilege escalation indicators

9. **Password Expiration Analysis** (`privileged-accounts-no-expire`)
   - Privileged account identification
   - Password expiration policy checking
   - Account context and risk scoring
   - Remediation recommendations

10. **Windows Feature Security** (`win-feature-security-check`)
    - Optional Windows feature enumeration
    - Risky component identification (SMB1, Telnet)
    - Feature configuration assessment
    - Security hardening suggestions

11. **Firewall Configuration** (`win-firewall-status-check`)
    - Windows Firewall profile analysis
    - Service state monitoring
    - Rule configuration assessment
    - Firewall security recommendations

12. **Update Management** (`win-update-check`)
    - Missing update enumeration
    - Critical/security update prioritization
    - Windows Update configuration review
    - Patch management recommendations

**Advanced/Wishlist Modules:**
1. **Password Strength Testing** (`password-crack`)
   - Weak password detection with lockout protection
   - Common password dictionary testing
   - Account lockout risk mitigation

2. **Kerberoasting Detection** (`kerberoasted-accounts`)
   - SPN enumeration and analysis
   - Kerberoast vulnerability assessment
   - Service account security evaluation

3. **SMB Signing Assessment** (`smb-signing-check`)
   - SMB signing requirement verification
   - Configuration mismatch detection
   - MITM attack risk assessment

### 3. SECURE COMMUNICATION

#### Agent-to-Dashboard Protocol
- **Encryption**: TLS 1.3 with certificate pinning
- **Authentication**: Mutual TLS or token-based authentication
- **Data Format**: Compressed JSON payloads
- **Error Handling**: Retry logic with exponential backoff
- **Logging**: Secure audit trail for all communications

#### Data Transmission Security
- **Payload Encryption**: End-to-end encryption for sensitive data
- **Data Integrity**: HMAC signatures for tamper detection
- **Rate Limiting**: Protection against abuse and DoS
- **Network Resilience**: Automatic failover and reconnection

---

## TECHNICAL SPECIFICATIONS

### ✅ IMPLEMENTED TECHNOLOGY STACK

#### Frontend Dashboard
- **Framework**: Next.js 15.5.3 with TypeScript
- **Styling**: Tailwind CSS with project-specific color scheme
- **Components**: Custom component library (Button, Card, RiskIndicator, Layout)
- **State Management**: Zustand (ready for implementation)
- **HTTP Client**: Axios (configured, ready for API integration)
- **Icons**: Lucide React
- **Testing**: Jest + React Testing Library (configured)

#### Backend API
- **Framework**: Node.js/Express with TypeScript
- **Database**: PostgreSQL with Prisma ORM v6.1.0
- **Security**: Helmet, CORS, rate limiting, bcryptjs
- **Logging**: Winston with structured logging
- **Validation**: Zod schemas + express-validator
- **Authentication**: JWT infrastructure (ready for implementation)

#### Database Schema (Prisma)
```prisma
// Core models implemented:
model Organization {
  id        String   @id @default(cuid())
  name      String
  settings  Json     @default("{}")
  // ... relations to users, agents, assessments
}

model User {
  id             String    @id @default(cuid())
  email          String    @unique
  role           UserRole  @default(USER)
  // ... authentication fields
}

model Agent {
  id             String          @id @default(cuid())
  hostname       String
  status         AgentStatus     @default(OFFLINE)
  // ... configuration and assessment relations
}

model Assessment {
  id               String            @id @default(cuid())
  status           AssessmentStatus  @default(PENDING)
  overallRiskScore Float?
  // ... results and reports relations
}
```

### 🔧 PENDING TECHNOLOGY INTEGRATION

#### Go Agent Development
- **Language**: Go 1.21+ for Windows compatibility
- **Architecture**: CLI application with modular assessment system
- **Communication**: HTTPS/TLS to dashboard API
- **Configuration**: YAML configuration files
- **Build**: Cross-compilation for Windows targets
- **Packaging**: Executable with embedded resources

---

## DESIGN SPECIFICATIONS

### Color Scheme and Branding

#### Primary Colors
- **Primary Blue**: #2563eb (Blue-600)
- **Secondary Blue**: #3b82f6 (Blue-500)
- **Light Blue**: #dbeafe (Blue-100)
- **Pure White**: #ffffff
- **Pure Black**: #000000
- **Dark Grey**: #374151 (Gray-700)
- **Medium Grey**: #6b7280 (Gray-500)
- **Light Grey**: #f3f4f6 (Gray-100)

#### Color Usage Guidelines
- **Headers/Navigation**: Dark blue (#2563eb) on white
- **Buttons**: Blue gradient with white text
- **Cards/Panels**: White background with light grey borders
- **Text**: Black for primary content, dark grey for secondary
- **Status Indicators**:
  - High Risk: Red (#dc2626)
  - Medium Risk: Orange (#ea580c)
  - Low Risk: Green (#16a34a)
  - Info: Blue (#2563eb)

#### Typography
- **Primary Font**: Inter or similar modern sans-serif
- **Headers**: Bold weights (600-700)
- **Body Text**: Regular weight (400)
- **Code/Technical**: Mono font (JetBrains Mono)

### Dashboard Layout
- **Sidebar Navigation**: Collapsible with icons and labels
- **Header**: Company logo, user profile, notifications
- **Main Content**: Cards-based layout with proper spacing
- **Footer**: Minimal with version and links

---

## REPORT SPECIFICATIONS

### HTML Report Template

#### Report Structure
1. **Executive Summary**
   - Company logo and assessment date
   - Overall risk score with visual indicator
   - High-level findings summary
   - Key recommendations

2. **Assessment Overview**
   - Scope and methodology
   - Systems assessed
   - Assessment duration
   - Agent version and configuration

3. **Risk Analysis Dashboard**
   - Risk score breakdown by category
   - Severity distribution chart
   - Trend analysis (if historical data available)
   - Critical findings highlight

4. **Detailed Findings**
   - Categorized by assessment module
   - Risk level indicators
   - Technical details and evidence
   - Specific remediation steps

5. **Remediation Roadmap**
   - Prioritized action items
   - Implementation timeline suggestions
   - Resource requirements
   - Follow-up recommendations

#### Report Styling
- **Professional Layout**: Clean, corporate design
- **Color Coding**: Risk levels with consistent color scheme
- **Charts and Graphs**: Interactive visualizations
- **Print-Friendly**: Proper page breaks and formatting
- **Export Options**: PDF generation capability

---

## DEVELOPMENT GUIDELINES

### Code Standards

#### Frontend Development
- **TypeScript**: Strict mode enabled, comprehensive type definitions
- **Component Structure**: Atomic design principles
- **Testing**: Jest and React Testing Library
- **Linting**: ESLint with security-focused rules
- **Formatting**: Prettier with consistent configuration

#### Backend Development
- **API Design**: RESTful with OpenAPI/Swagger documentation
- **Error Handling**: Structured error responses with proper HTTP codes
- **Logging**: Comprehensive audit logging for security events
- **Testing**: Unit and integration tests with high coverage
- **Security**: Input validation, rate limiting, CORS configuration

#### Agent Development
- **Performance**: Minimal resource usage and fast execution
- **Error Recovery**: Graceful handling of permission issues
- **Compatibility**: Support for Windows Server 2016+
- **Security**: Code signing and integrity verification
- **Documentation**: Comprehensive usage and troubleshooting guides

### Security Considerations

#### Authentication and Authorization
- **Multi-factor Authentication**: Support for TOTP/SMS
- **Role-Based Access Control**: Granular permissions system
- **Session Management**: Secure session handling with proper expiration
- **API Security**: Rate limiting, input validation, SQL injection prevention

#### Data Protection
- **Encryption at Rest**: Database and file storage encryption
- **Encryption in Transit**: TLS for all communications
- **Data Retention**: Configurable retention policies
- **Privacy**: GDPR/compliance-ready data handling

---

## DEPLOYMENT AND OPERATIONS

### Infrastructure Requirements

#### Minimum System Requirements
- **CPU**: 4 cores
- **RAM**: 8GB
- **Storage**: 100GB SSD
- **Network**: 100Mbps with static IP
- **OS**: Ubuntu 22.04 LTS or similar

#### Scalability Considerations
- **Horizontal Scaling**: Load balancer support
- **Database**: Read replicas and connection pooling
- **Caching**: Redis for session and query caching
- **Monitoring**: Prometheus/Grafana integration

### Deployment Methods
- **Docker Containers**: Production-ready containerization
- **CI/CD Pipeline**: Automated testing and deployment
- **Environment Management**: Dev/staging/production configurations
- **Backup Strategy**: Automated database and file backups

---

## SUCCESS CRITERIA

### Performance Targets
- **Dashboard Load Time**: < 2 seconds
- **Agent Execution Time**: < 5 minutes for full assessment
- **Report Generation**: < 30 seconds for comprehensive report
- **Concurrent Users**: Support 50+ simultaneous dashboard users
- **Agent Scalability**: Handle 1000+ agents per dashboard instance

### Quality Metrics
- **Code Coverage**: > 80% for critical components
- **Uptime**: 99.9% availability target
- **Security**: Zero critical vulnerabilities in production
- **User Experience**: Intuitive interface with minimal training required

---
### Risk Calculation
- **Critical**: 90-100 (immediate action required)
- **High**: 70-89 (address within 30 days)
- **Medium**: 40-69 (address within 90 days)
- **Low**: 0-39 (address during next maintenance window)

### Development Environment
- **Local Setup**: Docker Compose for full stack
- **Testing**: Staging environment requirements
- **CI/CD**: GitHub Actions workflow specifications
---

## PHASE 1 COMPLETION ROADMAP

### 🎯 IMMEDIATE TASKS (Next 2-3 Weeks)

#### TASK 1: Core API Endpoints (Week 1)
**Objective**: Enable frontend-backend communication for agents and assessments
**Acceptance Criteria**:
- All 11 API endpoints functional and tested
- Zod validation schemas for all request/response types
- Proper error handling with HTTP status codes
- JWT authentication middleware protecting all routes
- Swagger/OpenAPI documentation generated

**Implementation Order**:
1. Create `src/controllers/agentController.ts` with all CRUD operations
2. Create `src/controllers/assessmentController.ts` with lifecycle management
3. Create `src/controllers/reportController.ts` with HTML generation
4. Create `src/routes/agents.ts`, `src/routes/assessments.ts`, `src/routes/reports.ts`
5. Add all routes to main server with authentication middleware
6. Test all endpoints with Postman/Thunder Client

#### TASK 2: Go Agent Framework (Week 2)
**Objective**: Working Go agent that can communicate with dashboard and run first assessment
**Acceptance Criteria**:
- Go CLI application with cobra framework
- YAML configuration file loading
- HTTPS client for API communication
- Agent registration on startup
- At least 1 working assessment module (`win-update-check`)
- JSON result output to dashboard

**Implementation Steps**:
1. Initialize Go module in `agents/` directory
2. Set up cobra CLI with commands: `register`, `run`, `status`
3. Create config structure and YAML loading
4. Implement HTTPS client with authentication
5. Build `win-update-check` module using Windows API
6. Create result submission to `/api/assessments/:id/results`

#### TASK 3: Dashboard Integration (Week 3)
**Objective**: Live data flow between frontend and backend
**Acceptance Criteria**:
- Authentication working end-to-end
- Agent list showing real agent data
- Assessment creation through UI
- Real-time assessment status updates
- Results visualization with actual data

**Implementation Steps**:
1. Create `src/services/agentApi.ts` and `src/services/assessmentApi.ts`
2. Update dashboard to use real API calls instead of mock data
3. Create Agents page showing registered agents
4. Create Assessment creation form
5. Update homepage metrics with real data
6. Add error handling and loading states

### 🎯 SUCCESS CRITERIA FOR PHASE 1 COMPLETION

#### Technical Milestones
1. **✅ Authentication**: User can register, login, and access protected routes
2. **🔄 API Layer**: All core endpoints functional with proper validation
3. **⏳ Agent Communication**: Go agent can register and submit assessment results
4. **⏳ Data Flow**: Frontend displays real data from backend
5. **⏳ First Assessment**: At least one Windows check working end-to-end

#### Functional Requirements
- New user can register and create organization
- User can download and configure Go agent
- Agent automatically registers with dashboard
- User can trigger assessment through dashboard
- Assessment results display in dashboard with risk scoring
- User can view assessment history and agent status

### 🔧 DEVELOPMENT ENVIRONMENT SETUP

#### Required for Next Phase
1. **PostgreSQL Database**: Local or Docker instance running
2. **Environment Variables**: Copy `.env.example` to `.env` with real values
3. **Go Development**: Go 1.21+ installed for agent development
4. **Database Migration**: Run `npm run db:push` in backend/
5. **Development Servers**:
   - Frontend: `npm run dev` (port 3000)
   - Backend: `npm run dev` (port 3001)

### 🚀 PHASE 2 PRIORITIES (4-6 weeks)

#### 1. Advanced Agent Modules
- Complete all 12 minimum requirement assessment modules
- Advanced modules (password-crack, kerberoasting, SMB signing)
- Performance optimization and error handling
- Comprehensive logging and debugging

#### 2. Report Generation System
- HTML report templates with professional styling
- PDF export functionality
- Executive summary generation
- Risk trend analysis and visualizations
- Customizable report branding

#### 3. Enhanced Dashboard Features
- Historical assessment data and trending
- Advanced filtering and search capabilities
- Multi-organization support and isolation
- User management and permissions
- Notification system for critical findings

### 📋 CRITICAL PATH TO PHASE 1 COMPLETION

#### Week 1: API Layer Foundation
**Days 1-2**: Agent Management APIs
- `agentController.ts` with registration, listing, configuration
- Input validation with Zod schemas
- Authentication middleware integration


**Days 3-4**: Assessment Management APIs
- `assessmentController.ts` with CRUD operations
- Result submission endpoint for agent data
- Status tracking and lifecycle management

**Day 5**: Report Generation APIs
- `reportController.ts` with HTML generation
- Template system for professional reports
- PDF export capability (stretch goal)

#### Week 2: Go Agent Development
**Days 1-2**: CLI Framework
- Cobra CLI setup with subcommands
- YAML configuration loading
- HTTPS client with JWT authentication

**Days 3-4**: Windows Assessment Module
- `win-update-check` implementation
- Windows API integration for update status
- JSON result formatting

**Day 5**: Agent-Dashboard Communication
- Registration flow with heartbeat
- Result submission to assessment endpoint
- Error handling and retry logic

#### Week 3: Dashboard Integration
**Days 1-2**: API Service Layer
- Frontend API clients for agents/assessments
- Replace mock data with real API calls
- Error handling and loading states

**Days 3-4**: Real-time Features
- Agent status monitoring
- Assessment creation workflow
- Results visualization

**Day 5**: End-to-End Testing
- Complete user journey testing
- Bug fixes and polish
- Documentation updates

### 🛠️ POST-PHASE 1 IMPROVEMENTS
**Technical Debt** (Phase 2 priorities):
- Comprehensive test coverage (Jest + React Testing Library)
- Docker development environment
- CI/CD pipeline with GitHub Actions
- API documentation with Swagger/OpenAPI
- Performance monitoring and alerting
- Additional Windows assessment modules (4 more)

### 📊 PHASE 1 COMPLETION METRICS
**Success Criteria** (All must be met):
1. **✅ User Registration**: New users can create accounts and organizations
2. **🔄 Agent Registration**: Go agent successfully registers with dashboard
3. **⏳ Assessment Execution**: User can trigger assessment through UI
4. **⏳ Result Display**: Assessment results appear in dashboard with risk scoring
5. **⏳ Data Persistence**: All data stored in PostgreSQL with proper relationships

**Performance Targets**:
- Dashboard loads in < 3 seconds
- Agent assessment completes in < 2 minutes
- API response times < 500ms
- Zero authentication bypass vulnerabilities
- All TypeScript builds without errors

---

  Todos
  ☒ Complete frontend dependencies installation
  ☒ Configure Tailwind CSS with project color scheme
  ☒ Set up basic component structure and layout
  ☒ Initialize backend Node.js/Express server with TypeScript
  ☒ Set up PostgreSQL database with Prisma ORM
  ☒ Implement JWT authentication backend endpoints
  ☒ Create authentication middleware and utilities
  ☒ Build frontend authentication components
  ☐ Create Agent Management API endpoints
  ☐ Create Assessment Management API endpoints
  ☐ Create Report Generation API endpoints
  ☐ Initialize Go agent framework with CLI structure
  ☐ Implement first Windows assessment module (win-update-check)
  ☐ Create agent-dashboard communication protocol
  ☐ Integrate real API data into frontend dashboard

*This document serves as the living specification for the cybersecurity assessment platform. Progress is tracked and updated as development continues.*