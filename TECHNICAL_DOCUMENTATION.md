# CyberNews - Technical Documentation

## Executive Summary

CyberNews is a threat intelligence aggregation platform designed for security analysts and operations centers. It automatically collects cybersecurity news, vulnerability data, and threat intelligence from multiple sources, processes threat data using AI extraction, and provides a web-based dashboard with role-based access control for threat analysis and incident tracking.

---

## 1. System Architecture Overview

### 1.1 Architecture Layers

```
┌─────────────────────────────────────────┐
│         Frontend Layer                  │
│  (Jinja2 Templates + Static Assets)     │
└────────────────┬────────────────────────┘
                 │
┌─────────────────────────────────────────┐
│         API & Web Layer                 │
│  (Flask Blueprints + REST Endpoints)    │
└────────────────┬────────────────────────┘
                 │
┌─────────────────────────────────────────┐
│    Business Logic & Services            │
│  (Feed Parsing, IOC Extraction, Jobs)   │
└────────────────┬────────────────────────┘
                 │
┌─────────────────────────────────────────┐
│      Data Layer                         │
│  (SQLAlchemy ORM + PostgreSQL/SQLite)   │
└─────────────────────────────────────────┘
```

### 1.2 Core Components

**Flask Application Factory (`app/__init__.py`)**
- Creates and configures Flask app instance
- Registers four blueprints: auth, news, admin, api
- Initializes database and ORM (SQLAlchemy)
- Sets up CORS for API cross-origin requests
- Starts background scheduler for automated feed processing
- Uses environment-specific configs (dev/prod/test)

**Database Layer (PostgreSQL/SQLite)**
- Primary: PostgreSQL for production
- Development: SQLite for local testing
- Flask-Migrate for schema versioning

**Background Job Scheduler**
- Runs every 30 minutes (configurable)
- Fetches RSS feeds from security news sources
- Triggers AI-powered threat analysis on new articles
- Extracts IOCs and maps to MITRE ATT&CK techniques

---

## 2. Data Models & Database Schema

### 2.1 User Model

```
TABLE: users
├── id (PK)
├── username (UNIQUE, INDEXED)
├── password_hash (bcrypt)
├── role (analyst_l1 | analyst_l2 | admin)
├── display_name
├── clearance (e.g., "Level 1 Analyst")
├── created_at (TIMESTAMP)
├── last_login (TIMESTAMP, nullable)
├── failed_attempts (INT - brute force protection)
└── locked_until (TIMESTAMP - account lockout)
```

**Purpose**: User authentication and authorization. Role determines data visibility and system permissions.

**Security Features**:
- Passwords hashed with bcrypt (never plaintext)
- Failed login attempts tracked (brute force mitigation)
- Account lockout mechanism after N failed attempts

### 2.2 NewsArticle Model

```
TABLE: news_articles
├── id (PK)
├── title (VARCHAR 500)
├── source (INDEXED - "The Hacker News", "SecurityWeek", etc.)
├── url (UNIQUE)
├── published_at (DATETIME, INDEXED)
├── category (INDEXED - Vulnerability, Breach, Threat Actor, Patch)
├── severity (INDEXED - Critical, High, Medium, Low)
├── summary (TEXT)
├── ai_summary (TEXT - AI-generated summary)
├── raw_content (TEXT)
├── epss_score (FLOAT - 0.0 to 1.0)
├── cve_id (VARCHAR 30, INDEXED)
├── internal_ip (VARCHAR - analyst annotations)
├── internal_note (TEXT - analyst annotations)
├── fetched_at (DATETIME)
├── ai_processed (BOOLEAN, INDEXED)
└── Relationships:
    ├── iocs (One-to-Many with IOC table)
    └── mitre_tags (One-to-Many with MitreTag table)
```

**Purpose**: Stores aggregated threat intelligence articles from RSS feeds.

**Key Fields**:
- `ai_processed`: Flag to track if Gemini AI has analyzed this article
- `internal_ip` + `internal_note`: Analyst annotations for internal threat tracking
- `epss_score`: CISA EPSS (Exploit Prediction Scoring System) for vulnerability prioritization

### 2.3 IOC (Indicator of Compromise) Model

```
TABLE: iocs
├── id (PK)
├── article_id (FK → news_articles.id, INDEXED, CASCADE DELETE)
├── type (VARCHAR - ip | domain | hash | cve | url)
├── value (VARCHAR 500 - actual IOC value)
├── first_seen (DATETIME)
└── UNIQUE CONSTRAINT: (article_id, type, value)
```

**Purpose**: Extracted threat indicators from articles. Analysts use IOCs to hunt threats in their infrastructure.

**Example IOCs**:
- **IP**: `192.168.1.1`, `10.0.0.50`
- **Domain**: `malicious.com`, `c2.attacker.org`
- **Hash**: MD5/SHA256 of malware samples
- **CVE**: `CVE-2024-6387`
- **URL**: `https://exploit.site/payload`

### 2.4 Incident Model

```
TABLE: incidents
├── id (PK)
├── title (VARCHAR 300)
├── severity (VARCHAR - Critical, High, Medium, Low)
├── status (VARCHAR, INDEXED - open | in_progress | resolved | closed)
├── assigned_to_id (FK → users.id, nullable)
├── description (TEXT)
├── created_at (DATETIME)
├── updated_at (DATETIME)
└── Relationships:
    └── assignee (User who owns this incident)
```

**Purpose**: Track security incidents identified through threat intelligence analysis.

**Workflow**: Analyst reviews articles → Creates incident → Assigns to team member → Updates status as investigation progresses.

### 2.5 AuditLog Model

```
TABLE: audit_log
├── id (PK)
├── event (VARCHAR 50, INDEXED - login, article_viewed, incident_created, etc.)
├── username (VARCHAR 80 - who performed action)
├── ip_address (VARCHAR 50)
├── timestamp (DATETIME, INDEXED)
└── extra (TEXT - additional context)
```

**Purpose**: Security audit trail for compliance and investigation.

**Logged Events**:
- User login/logout
- Article views
- Incident creation/modification
- Data exports
- Admin actions

### 2.6 MitreTag Model

```
TABLE: mitre_tags
├── id (PK)
├── article_id (FK → news_articles.id, INDEXED, CASCADE DELETE)
├── technique_id (VARCHAR - e.g., "T1059.001")
├── technique_name (VARCHAR 200 - e.g., "Command and Scripting Interpreter")
├── tactic (VARCHAR - e.g., "Execution")
├── confidence (VARCHAR - high | medium | low)
└── ai_suggested (BOOLEAN - True if AI auto-tagged, False if manually added)
```

**Purpose**: Maps threat articles to MITRE ATT&CK framework for threat classification.

**Example**:
- Article about Lazarus Group → T1204 (User Execution), T1566 (Phishing)
- Article about Windows privilege escalation → T1547 (Boot or Logon Autostart Execution)

---

## 3. Web Application Features

### 3.1 Authentication & Authorization System

**Blueprint**: `app/blueprints/auth.py`

**Features**:
- JWT token-based authentication for API endpoints
- Session-based authentication for web interface
- Role-based access control (RBAC) with three tiers

**Roles & Permissions**:

| Role | Permissions |
|------|------------|
| **Level 1 Analyst** (`analyst_l1`) | View articles, search by severity, view MITRE tags, cannot see internal IPs/notes, cannot create incidents |
| **Level 2 Analyst** (`analyst_l2`) | Level 1 + View internal IP/notes, create/view incidents, update incident status, export threat data |
| **Administrator** (`admin`) | Full system access - user management, audit logs, scheduler control, data purging |

**Data Redaction**:
- Level 1 analysts see: `[REDACTED]` for `internal_ip` field
- Level 1 analysts see: `[REDACTED — INSUFFICIENT CLEARANCE]` for `internal_note` field
- IOC list hidden from Level 1 analysts (returns empty array)

**Security Mechanisms**:
- Passwords hashed with bcrypt (not reversible)
- Failed login tracking with account lockout
- Session timeout (24 hours)
- CSRF protection on forms

### 3.2 News Feed Management

**Blueprint**: `app/blueprints/news.py`

**Pages**:

**Dashboard (`/`)**
- Displays recent threat articles
- Shows severity distribution (pie/bar chart)
- Lists top threat sources
- Filtering by: source, severity, category, date range
- Search functionality across title/summary

[SCREENSHOT PLACEHOLDER: Dashboard homepage - Show article feed with severity color coding, filter dropdown options, and article cards with titles/sources]

**Article Detail Page (`/article/<id>`)**
- Full article with source link
- Extracted IOCs table (if Level 2+ analyst)
- MITRE ATT&CK tags with tactics
- Internal annotations (if applicable to role)
- Related incidents
- Publication date and EPSS score (if CVE)

[SCREENSHOT PLACEHOLDER: Article detail view - Show full article content, IOCs table with type/value columns, MITRE tags section, internal notes area]

**IOCs Gallery (`/iocs`)**
- Table of all extracted indicators from threat articles
- Filterable by type (IP, domain, hash, CVE, URL)
- Search by value
- Level 2+ only can see this page
- Export to CSV or JSON

[SCREENSHOT PLACEHOLDER: IOCs page - Show table with columns: Type | Value | Article | Source | Date - with filter controls and export buttons]

**Incidents Tracker (`/incidents`)**
- List of open, in-progress, and resolved security incidents
- Create new incident from article
- Assign incident to team member
- Update incident status and description
- Linked to threat articles for context

[SCREENSHOT PLACEHOLDER: Incidents page - Show incident list with columns: Title | Severity | Status | Assigned To | Created Date - with status update controls]

### 3.3 Administrative Functions

**Blueprint**: `app/blueprints/admin.py` (URL prefix: `/admin`)

**Admin Dashboard (`/admin`)**
- System statistics (total articles, IOCs, users, incidents)
- Scheduler status (last run, next run time)
- Database size
- Recent audit log entries

[SCREENSHOT PLACEHOLDER: Admin dashboard - Show stat cards (Articles: X, IOCs: Y, Users: Z), Scheduler status indicator, recent audit log preview]

**User Management (`/admin/users`)**
- Create/edit/delete users
- Assign roles (analyst_l1, analyst_l2, admin)
- Set clearance levels
- Reset user passwords
- View user creation date and last login

[SCREENSHOT PLACEHOLDER: User management - Show user table with columns: Username | Display Name | Role | Clearance | Created | Last Login - with edit/delete action buttons]

**Audit Logs (`/admin/audit-logs`)**
- View all user actions (login, article views, incident updates)
- Filter by event type, username, date range
- Export audit logs for compliance

[SCREENSHOT PLACEHOLDER: Audit logs page - Show table with columns: Event | Username | IP Address | Timestamp | Details - with date range picker]

**Feed Configuration (`/admin/scheduler`)**
- View configured RSS feed sources
- Add/remove feed sources
- Adjust scheduler interval (default 30 minutes)
- Manual trigger for feed refresh
- View scheduler logs (errors, fetched count)

[SCREENSHOT PLACEHOLDER: Scheduler config - Show feed sources list with enable/disable toggles, interval slider input, Manual Refresh button, recent job logs]

### 3.4 API Endpoints

**Blueprint**: `app/blueprints/api.py` (URL prefix: `/api`)

All API endpoints require Bearer token authentication.

**News Endpoints**:
```
GET  /api/articles
     Query params: source, severity, category, search, page, limit
     Response: Paginated article list

GET  /api/articles/<id>
     Response: Full article with IOCs and MITRE tags

GET  /api/articles/<id>/iocs
     Response: IOCs extracted from article

GET  /api/articles/<id>/mitre
     Response: MITRE tags for article

POST /api/articles/<id>/note
     Body: { "internal_note": "...", "internal_ip": "..." }
     Response: Updated article
```

**Incident Endpoints**:
```
GET  /api/incidents
     Query params: status, severity, assigned_to, page, limit
     Response: Paginated incident list

POST /api/incidents
     Body: { "title": "...", "severity": "...", "description": "..." }
     Response: Created incident

GET  /api/incidents/<id>
     Response: Full incident details

PATCH /api/incidents/<id>
      Body: { "status": "...", "assigned_to_id": ... }
      Response: Updated incident
```

**User Endpoints** (Admin only):
```
GET  /api/users
     Response: List of all users

POST /api/users
     Body: { "username": "...", "role": "...", "display_name": "..." }
     Response: Created user

PATCH /api/users/<id>
      Body: { "role": "...", "clearance": "..." }
      Response: Updated user
```

---

## 4. Background Services & AI Integration

### 4.1 RSS Feed Fetcher

**Service**: `app/services/feed_fetcher.py`

**Functionality**:
1. Runs every 30 minutes (controlled by `SCHEDULER_INTERVAL_MINUTES` env var)
2. Fetches from configured RSS feed sources
3. Parses article titles, descriptions, publication dates, source URLs
4. Deduplicates by URL (prevents duplicate entries)
5. Stores new articles in database with `ai_processed=False`
6. Maximum 10 articles queued per run for AI processing

**Supported Sources** (hardcoded in config):
- The Hacker News RSS
- SecurityWeek RSS
- CISA Alerts RSS

**Error Handling**:
- Logs fetch failures without stopping scheduler
- Retries on network timeouts
- Deduplicates on URL collision

### 4.2 Gemini AI Service

**Service**: `app/services/gemini_service.py`

**Purpose**: Analyze threat articles using Google Gemini API to extract IOCs and map techniques.

**Process**:
1. Picks unprocessed articles (up to 10 per cycle)
2. Sends article content to Gemini API with custom prompt
3. Receives structured response with extracted IOCs and techniques
4. Parses response and stores in database

**Extraction Capabilities**:
- **IPs**: IPv4/IPv6 addresses (e.g., `192.168.1.1`)
- **Domains**: DNS names (e.g., `malicious.com`, `c2.attacker.org`)
- **Hashes**: MD5, SHA256 (e.g., malware signatures)
- **CVEs**: Vulnerability IDs (e.g., `CVE-2024-6387`)
- **URLs**: Full HTTP/HTTPS links (e.g., `https://exploit.site/payload`)

**MITRE ATT&CK Mapping**:
- Identifies threat techniques from article context
- Example: Article mentions "ransomware encryption" → T1486 (Data Encrypted for Impact)
- Stores technique ID, name, tactic, and confidence level

**API Key Required**:
- Set via `GEMINI_API_KEY` environment variable
- Rate limits depend on Google Cloud quota
- Handles API errors gracefully

### 4.3 IOC Extractor

**Service**: `app/services/ioc_extractor.py`

**Purpose**: Standalone IOC extraction utility (called by Gemini service).

**Features**:
- Regex-based IOC detection as fallback if Gemini fails
- Supports patterns: IPs, domains, hashes, URLs
- Validates extracted values before storage
- Prevents false positives (e.g., localhost IPs)

### 4.4 Scheduler

**Service**: `app/services/scheduler.py`

**Implementation**: APScheduler (Advanced Python Scheduler)

**Job Scheduling**:
```
Interval-based jobs:
├── feed_fetcher.fetch_rss()        Every 30 minutes
├── gemini_service.process_articles() Every 30 minutes (offset)
└── cleanup_old_logs()              Daily at 2 AM
```

**Error Handling**:
- Catches exceptions in jobs to prevent scheduler crash
- Logs errors to application logger
- Continues running even if single job fails

---

## 5. Security Considerations

### 5.1 Authentication Security

- **Password Storage**: bcrypt with salt (not plaintext, not simple hashing)
- **Session Management**: Flask sessions with secure cookies
- **JWT Tokens**: Bearer tokens for API authentication
- **CORS**: Restricted to configured origins

### 5.2 Data Access Control

- **Row-Level Security**: `to_dict(role)` method redacts sensitive fields based on user role
- **Internal IP/Notes**: Hidden from Level 1 analysts
- **IOCs**: Not visible to Level 1 analysts
- **Audit Trail**: All user actions logged for compliance

### 5.3 Database Security

- **SQL Injection Prevention**: SQLAlchemy ORM prevents SQL injection
- **Unique Constraints**: Prevents duplicate IOCs `(article_id, type, value)`
- **Foreign Key Constraints**: Cascade deletes maintain referential integrity
- **Indexing**: Critical fields indexed for performance (username, cve_id, severity, etc.)

### 5.4 Input Validation

- **URL Uniqueness**: Prevents duplicate articles
- **Role Validation**: Only valid roles accepted
- **Severity Levels**: Enumerated to prevent invalid values
- **API Input Sanitization**: Limits query parameter lengths

---

## 6. Environment Configuration

**Development** (`FLASK_ENV=development`):
- Debug mode enabled
- SQLite local database
- Insecure cookies (HTTP-only)
- Verbose logging

**Production** (`FLASK_ENV=production`):
- Debug disabled
- PostgreSQL database
- Secure cookies (HTTPS-only)
- Minimal logging (performance)

**Testing** (`FLASK_ENV=testing`):
- In-memory SQLite
- CSRF disabled
- Fake Gemini API responses

---

## 7. Deployment Architecture

**Local Development**:
```
Python venv → Flask dev server → SQLite → Localhost:5000
```

**Production** (Render):
```
GitHub Repo → Render Build → Gunicorn → PostgreSQL → HTTPS
             ↓
        APScheduler (background jobs)
        Gemini API (threat analysis)
```

---

## 8. User Workflows

### 8.1 Level 1 Analyst Workflow

1. **Login**: Navigate to `/login`, enter credentials
2. **Browse Feed**: View dashboard articles sorted by severity
3. **Read Articles**: Click article → view summary, category, EPSS score
4. **See MITRE Tags**: Identify threat tactics (but not internals)
5. **Cannot**: View IOCs, internal notes, create incidents

### 8.2 Level 2 Analyst Workflow

1. **Login**: Same as L1
2. **Browse & Read**: Same as L1
3. **Extract Threat Intelligence**:
   - View `/iocs` page with extracted indicators
   - See internal IPs and notes from colleagues
   - Export IOCs to CSV for SIEM ingestion
4. **Incident Response**:
   - Create incident from article (e.g., "CVE-2024-6387 exploitation attempt")
   - Assign to team member
   - Update status as investigation progresses
   - Link incidents to articles for context

### 8.3 Administrator Workflow

1. **System Monitoring**: Check `/admin` dashboard for system health
2. **User Management**: Add analysts, assign roles, reset passwords
3. **Feed Management**: Configure RSS sources, manually trigger refresh
4. **Audit Compliance**: Export audit logs for regulatory reports
5. **Troubleshooting**: View scheduler logs, check error rates

---

## 9. Data Flow Diagram

```
[RSS Sources]
    ↓ (Every 30 min)
[Feed Fetcher] → Fetches & Deduplicates
    ↓
[Database] → Store articles with ai_processed=False
    ↓
[Gemini AI] → Analyzes up to 10 articles per cycle
    ↓
[IOC Extractor] → Extracts: IPs, domains, hashes, CVEs
[MITRE Mapper] → Maps to ATT&CK techniques
    ↓
[Database] → Update articles with IOCs, MITRE tags, ai_processed=True
    ↓
[Web Interface]
    ├─ Dashboard (All users)
    ├─ Article Detail (All users)
    ├─ IOCs Page (L2+ only)
    ├─ Incidents (L2+ only)
    └─ Admin (Admin only)
    ↓
[Analysts] → Review threats, create incidents, update status
```

---

## 10. Technology Stack Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Web Framework | Flask 3.0.3 | HTTP server, routing, sessions |
| Database ORM | SQLAlchemy 2.0.31 | Object-relational mapping |
| Database | PostgreSQL/SQLite | Data persistence |
| Authentication | bcrypt, JWT | Secure password hashing, token auth |
| Background Jobs | APScheduler 3.10.4 | Scheduled feed fetching & AI processing |
| AI API | Google Generative AI (Gemini) | Threat analysis & IOC extraction |
| RSS Parsing | feedparser 6.0.11 | Parse security news feeds |
| HTTP Client | requests 2.32.3 | External API calls |
| CORS | flask-cors 4.0.1 | Cross-origin API requests |
| Server | Gunicorn 22.0.0 | Production WSGI server |
| Migrations | Flask-Migrate 4.0.7 | Database schema versioning |
| Environment | python-dotenv 1.0.1 | Load .env configuration |

---

## 11. Key Design Decisions

### 11.1 Role-Based Redaction

Instead of querying different data, the same database record is returned but fields are redacted in `to_dict(role)` method. This ensures:
- Single source of truth in database
- Easier maintenance (no duplicate queries)
- Clear separation of concerns
- Audit trail shows what data user tried to access (even if redacted)

### 11.2 AI Processing Asynchronously

Articles are marked `ai_processed=False` when fetched, then processed in background jobs (up to 10 per cycle). This ensures:
- Feed fetching doesn't block on slow AI API
- System degrades gracefully if Gemini API is down
- Scheduler can retry failed processing
- Users see articles immediately even if analysis is pending

### 11.3 MITRE Tags with Confidence & Source

Each MITRE tag stores:
- `technique_id` (e.g., T1204.001)
- `ai_suggested` (True if Gemini auto-tagged, False if manually added)
- `confidence` (high/medium/low)

This allows analysts to trust human-verified tags more than AI suggestions.

### 11.4 Cascading Deletes

Article deletion cascades to IOCs and MITRE tags:
```python
iocs = db.relationship("IOC", cascade="all, delete-orphan")
mitre_tags = db.relationship("MitreTag", cascade="all, delete-orphan")
```

This prevents orphaned IOCs when an article is deleted.

---

## 12. Future Considerations

- Integration with SIEM systems (Splunk, ELK)
- Multi-source IOC correlation (find same IP across articles)
- Threat actor tracking (group articles by threat group)
- API rate limiting per user
- Database query result caching
- WebSocket real-time feed updates
- Machine learning to detect anomalous news patterns
