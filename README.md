# CyberNews — Full-Stack Threat Intelligence Platform

A comprehensive threat intelligence platform that aggregates cybersecurity news, vulnerability data, and threat intelligence from multiple sources, enriched with AI-powered IOC (Indicators of Compromise) extraction and MITRE ATT&CK technique mapping.

## 🎯 Overview

**CyberNews** is a full-stack web application built to streamline threat intelligence gathering for security analysts, SOC teams, and security operations personnel. It integrates:

- **Live RSS Feeds**: Real-time vulnerability and threat news from The Hacker News and SecurityWeek
- **CISA KEV Catalog**: Critical Known Exploited Vulnerabilities for compliance and incident response
- **Google Gemini AI**: Automated IOC extraction and MITRE ATT&CK technique identification
- **Role-Based Access Control**: Multi-tier authentication with analyst and admin roles
- **Internal Annotations**: Integrate alerts with your own threat intelligence and internal tracking systems

### Key Features

✅ **Real-Time Threat Feed Aggregation** — Automatic RSS parsing and article ingestion  
✅ **AI-Powered Threat Analysis** — Google Gemini API extracts IOCs and maps to MITRE ATT&CK  
✅ **Vulnerability Intelligence** — CVE tracking with EPSS scores and exploitability data  
✅ **Role-Based Dashboard** — Separate views for L1 analysts, L2 analysts, and administrators  
✅ **Internal Threat Tracking** — Annotate articles with internal IP ranges, ticket IDs, and notes  
✅ **Secure Authentication** — JWT-based API, bcrypt password hashing, CSRF protection  
✅ **Production-Ready** — Deployed on Render with PostgreSQL and Gunicorn  

---

## 🏗️ Architecture

### Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Flask 3.0.3, Flask-SQLAlchemy, Flask-Migrate |
| **Database** | PostgreSQL (production), SQLite (dev) |
| **Authentication** | bcrypt, JWT Bearer tokens |
| **AI/ML** | Google Generative AI (Gemini) |
| **Scheduling** | APScheduler (background RSS feeds) |
| **Server** | Gunicorn (production), Flask dev server (local) |
| **Utilities** | feedparser, requests |

### Project Structure

```
cybernews/
├── app/                        # Flask application package
│   ├── __init__.py            # App factory (create_app)
│   ├── models.py              # SQLAlchemy ORM models (User, NewsArticle, etc.)
│   ├── routes/                # API routes and views
│   │   ├── auth.py            # Login, logout, token management
│   │   ├── articles.py        # Article CRUD and filtering
│   │   ├── analytics.py       # Threat metrics and reporting
│   │   └── admin.py           # Admin-only operations
│   ├── services/              # Business logic
│   │   ├── rss_feed.py        # RSS feed parsing and ingestion
│   │   ├── gemini_ai.py       # Google Gemini IOC extraction
│   │   ├── cisa_kev.py        # CISA KEV vulnerability sync
│   │   └── threat_mapper.py   # MITRE ATT&CK mapping
│   ├── utils/                 # Helper utilities
│   └── templates/             # Jinja2 HTML templates (if applicable)
├── config.py                   # Configuration management (dev/prod/test)
├── run.py                      # Application entry point
├── seed.py                     # Database seeding script
├── requirements.txt            # Python dependencies
├── .env.example               # Environment variables template
├── .gitignore                 # Git ignore patterns
├── LICENSE                    # MIT License
└── README.md                  # This file
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.9+**
- **PostgreSQL** (production) or SQLite (development)
- **Google Gemini API Key** (for AI-powered IOC extraction)
- **Flask environment** knowledge

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/4njuT0m/cybernews.git
cd cybernews
```

#### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Configure Environment Variables

Copy and configure `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Flask Secret Key (generate with: python -c "import secrets; print(secrets.token_hex(32))")
SECRET_KEY=your_32_byte_hex_secret_key_here

# Bearer Token for API authentication
BEARER_TOKEN=your_api_bearer_token_here

# Google Gemini API Key (get from https://ai.google.dev)
GEMINI_API_KEY=your_google_gemini_api_key_here

# Database URL (optional; defaults to SQLite)
DATABASE_URL=postgresql://user:password@localhost/cybernews_db

# Flask environment
FLASK_ENV=development

# Scheduler configuration
SCHEDULER_INTERVAL_MINUTES=30
PORT=5000
```

#### 5. Initialize Database

```bash
# Create database tables
python -c "from app import create_app; from app import db; app = create_app(); db.create_all()"

# (Optional) Seed with test data
python seed.py
```

### Running Locally

#### Development

```bash
python run.py
```

Access the application at `http://localhost:5000`

**Test Credentials** (after seeding):
- **analyst1** / `analyst1pass` (Level 1 Analyst)
- **analyst2** / `analyst2pass` (Level 2 Analyst)
- **admin** / `adminpass` (Administrator)

#### Production

```bash
gunicorn run:app -c gunicorn.conf.py
```

---

## 📋 Database Models

### User Model
```python
- username (str, unique)
- password_hash (str)
- role (str): "analyst_l1", "analyst_l2", "admin"
- display_name (str)
- clearance (str)
- last_login (datetime)
```

### NewsArticle Model
```python
- title (str)
- source (str): "The Hacker News", "SecurityWeek", "CISA", etc.
- url (str, unique)
- published_at (datetime)
- category (str): "Vulnerability", "Breach", "Threat Actor", "Patch", etc.
- severity (str): "Critical", "High", "Medium", "Low"
- summary (str)
- cve_id (str, nullable)
- epss_score (float, nullable): 0.0-1.0
- internal_ip (str, nullable)
- internal_note (str, nullable)
- ai_processed (bool)
- iocs_extracted (json, nullable): ["192.168.1.1", "domain.com", ...]
- mitre_techniques (json, nullable): ["T1059", "T1086", ...]
- created_at (datetime)
```

---

## 🔄 Background Jobs

### RSS Feed Scheduler

Automatically runs every **30 minutes** (configurable via `SCHEDULER_INTERVAL_MINUTES`):

1. Fetches articles from The Hacker News and SecurityWeek RSS feeds
2. Parses and deduplicates articles
3. Stores new articles in the database
4. Triggers AI processing for non-processed articles (max 10 per run)

### AI Processing Pipeline

For each unprocessed article:

1. **Google Gemini** analyzes article text to extract IOCs:
   - IP addresses
   - Domain names
   - File hashes
   - CVE IDs
2. Maps threat techniques to **MITRE ATT&CK** framework
3. Stores results in `iocs_extracted` and `mitre_techniques` JSON fields
4. Marks article as `ai_processed=True`

---

## 🔐 Authentication & Authorization

### JWT Bearer Token

All API endpoints require a valid Bearer token:

```bash
curl -H "Authorization: Bearer YOUR_BEARER_TOKEN" \
  http://localhost:5000/api/articles
```

### Role-Based Access Control

| Role | Permissions |
|------|------------|
| **Level 1 Analyst** (`analyst_l1`) | View articles, filter by severity, basic search |
| **Level 2 Analyst** (`analyst_l2`) | L1 permissions + view internal notes and IOCs |
| **Admin** (`admin`) | All permissions + user management, scheduler control, config updates |

---

## 📡 API Endpoints (Examples)

### Articles

#### Get All Articles
```bash
GET /api/articles?source=The%20Hacker%20News&severity=Critical
Authorization: Bearer YOUR_TOKEN
```

**Query Parameters:**
- `source`: Filter by feed source
- `severity`: Filter by severity level
- `category`: Filter by category
- `search`: Full-text search in title/summary
- `page`: Pagination (default: 1)
- `limit`: Results per page (default: 20)

#### Get Single Article
```bash
GET /api/articles/<id>
Authorization: Bearer YOUR_TOKEN
```

#### Update Internal Notes
```bash
PATCH /api/articles/<id>
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json

{
  "internal_ip": "10.42.0.11",
  "internal_note": "Affects 3 DMZ prod servers — ticket INC-4821"
}
```

### Authentication

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "analyst1",
  "password": "analyst1pass"
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "analyst1",
    "role": "analyst_l1",
    "display_name": "J. Carter"
  }
}
```

#### Logout
```bash
POST /api/auth/logout
Authorization: Bearer YOUR_TOKEN
```

---

## 🛠️ Configuration

### `config.py` Environments

#### Development
```python
DEBUG = True
SQLALCHEMY_DATABASE_URI = "sqlite:///cybernews_dev.db"
SESSION_COOKIE_SECURE = False
```

#### Production
```python
DEBUG = False
SQLALCHEMY_DATABASE_URI = "postgresql://..."
SESSION_COOKIE_SECURE = True
```

#### Testing
```python
TESTING = True
SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|------------|
| `SECRET_KEY` | ✅ | — | Flask session secret (32-byte hex) |
| `BEARER_TOKEN` | ✅ | — | API authentication token |
| `GEMINI_API_KEY` | ✅ | — | Google Gemini API key |
| `DATABASE_URL` | ❌ | `sqlite:///cybernews_dev.db` | Database connection string |
| `FLASK_ENV` | ❌ | `development` | `development`, `production`, `testing` |
| `SCHEDULER_INTERVAL_MINUTES` | ❌ | 30 | RSS feed refresh interval |
| `PORT` | ❌ | 5000 | Server port |

---

## 📦 Dependencies

See `requirements.txt`:

```
Flask==3.0.3                  # Web framework
Flask-SQLAlchemy==3.1.1       # ORM integration
Flask-Migrate==4.0.7          # Database migrations
flask-cors==4.0.1             # CORS handling
psycopg2-binary==2.9.9        # PostgreSQL adapter
SQLAlchemy==2.0.31            # Database ORM
bcrypt==4.1.3                 # Password hashing
APScheduler==3.10.4           # Background jobs
feedparser==6.0.11            # RSS parsing
requests==2.32.3              # HTTP client
google-generativeai==0.7.2    # Gemini AI API
python-dotenv==1.0.1          # Environment variables
gunicorn==22.0.0              # Production server
```

---

## 🧪 Testing & Seeding

### Seed Database with Test Data

```bash
python seed.py
```

Creates:
- 3 test users (analyst1, analyst2, admin)
- 12 sample threat intelligence articles
- Test data including CVE IDs, EPSS scores, internal IPs, and mock IOCs

### Manual Testing

```bash
# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"analyst1pass"}'

# Get articles with token
curl http://localhost:5000/api/articles \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🚀 Deployment

### Render Deployment

This application is configured for deployment on **Render**:

1. Connect GitHub repository to Render
2. Set environment variables in Render dashboard:
   - `SECRET_KEY`
   - `BEARER_TOKEN`
   - `GEMINI_API_KEY`
   - `DATABASE_URL` (Render PostgreSQL)
   - `FLASK_ENV=production`

3. Configure build and start commands:
   ```
   Build: pip install -r requirements.txt && python seed.py
   Start: gunicorn run:app -c gunicorn.conf.py
   ```

4. Deploy and monitor logs

---

## 🔄 Data Flow

```
RSS Feeds (Hacker News, SecurityWeek)
         ↓
    [APScheduler - every 30 min]
         ↓
   [feedparser - parse RSS]
         ↓
[Deduplicate & store in DB]
         ↓
  [Google Gemini AI]
         ↓
[IOC Extraction + MITRE ATT&CK Mapping]
         ↓
[Dashboard / API Endpoints]
         ↓
    [Security Analysts]
```

---

## 📊 Use Cases

### SOC Analysts
- Monitor live threat feeds without visiting multiple websites
- Quickly identify critical vulnerabilities affecting infrastructure
- Correlate IOCs with internal threat intel and SIEM data

### Compliance Teams
- Track CISA KEV updates for regulatory requirements (BOD 22-01)
- Generate compliance reports from ingested threat data

### Incident Response
- Fast IOC lookup during active incidents
- Cross-reference threat actor techniques with internal attack surface

### Security Researchers
- Aggregate threat intelligence from trusted sources
- Analyze threat patterns and emerging attack techniques

---

## 🐛 Troubleshooting

### Issue: `SECRET_KEY not set`
```bash
python -c "import secrets; print(secrets.token_hex(32))"
# Copy output to .env SECRET_KEY
```

### Issue: Database connection fails
- Check `DATABASE_URL` format
- Ensure PostgreSQL service is running (if not using SQLite)
- Verify credentials in connection string

### Issue: Gemini API errors
- Verify `GEMINI_API_KEY` is valid and not expired
- Check API quota in Google Cloud Console
- Ensure API is enabled for your project

### Issue: RSS feeds not updating
- Check `SCHEDULER_INTERVAL_MINUTES` is set correctly
- Verify APScheduler is running (check logs for errors)
- Manually trigger feed update: `python -c "from app.services import rss_feed; rss_feed.fetch_feeds()"`

---

## 📝 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes (`git commit -m "Add your feature"`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

---

## 📞 Support & Contact

For issues, feature requests, or questions:
- Open a GitHub Issue
- Contact the maintainer: [@4njuT0m](https://github.com/4njuT0m)

---

## 🗺️ Roadmap

- [ ] STIX/TAXII format support for threat data exchange
- [ ] Multi-source integration (AlienVault OTX, VirusTotal)
- [ ] Custom alert rules and webhooks
- [ ] Advanced filtering and saved searches
- [ ] Dark mode for dashboard
- [ ] Automated email summaries for analysts
- [ ] Mobile-responsive dashboard

---

**Last Updated:** May 2026  
**Status:** Active Development
