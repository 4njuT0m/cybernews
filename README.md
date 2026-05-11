# CyberNews

A threat intelligence platform built to understand full-stack development, API design, and cybersecurity fundamentals. The project integrates live threat feeds, vulnerability data, and demonstrates AI-powered threat analysis concepts.

## About

This is a learning project developed during cybersecurity training to understand:

- Building secure web applications with role-based access control (RBAC)
- Integrating multiple threat intelligence sources (RSS feeds, CISA KEV)
- API authentication and authorization using JWT tokens
- Threat data modeling and IOC (Indicator of Compromise) extraction
- Background job scheduling for automated threat feed ingestion
- Database design for security operations use cases

The project aggregates cybersecurity news from The Hacker News and SecurityWeek, integrates CISA Known Exploited Vulnerabilities, and uses Google Gemini AI to extract IOCs and map threats to MITRE ATT&CK techniques.

## Tech Stack

- Backend: Flask, SQLAlchemy
- Database: PostgreSQL (production), SQLite (development)
- Authentication: JWT, bcrypt
- Scheduling: APScheduler
- AI: Google Generative AI (Gemini)
- Feed Parsing: feedparser

## Project Structure

```
cybernews/
├── app/
│   ├── __pycache__/
│   ├── blueprints/
│   ├── __init__.py              # App factory
│   ├── admin.py                 # Admin operations
│   ├── api.py                   # API endpoints
│   ├── auth.py                  # Authentication routes
│   ├── news.py                  # News/article routes
│   ├── services/
│   │   ├── __pycache__/
│   │   ├── __init__.py
│   │   ├── feed_fetcher.py      # RSS feed parsing
│   │   ├── gemini_service.py    # IOC extraction
│   │   ├── ioc_extractor.py     # IOC processing
│   │   └── scheduler.py         # Background job scheduling
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── main.js
│   ├── templates/               # HTML templates
│   │   ├── admin.html
│   │   ├── base.html
│   │   ├── error.html
│   │   ├── incidents.html
│   │   ├── index.html
│   │   ├── iocs.html
│   │   └── login.html
│   ├── __init__.py
│   └── models.py                # Database models
├── venv/
├── .env                         # Environment variables (local)
├── .gitignore
├── config.py                    # Configuration
├── requirements.txt
└── run.py                       # Entry point
└── seed.py                      # Database seeding
```

## Installation & Setup

1. Clone the repository
   ```
   git clone https://github.com/4njuT0m/cybernews.git
   cd cybernews
   ```

2. Create virtual environment
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies
   ```
   pip install -r requirements.txt
   ```

4. Configure environment
   ```
   cp .env.example .env
   ```
   
   Edit `.env`:
   ```
   SECRET_KEY=your_secret_key_here
   BEARER_TOKEN=your_bearer_token_here
   GEMINI_API_KEY=your_gemini_api_key_here
   # Database (Supabase)
   DATABASE_URL=your_Database url_here
   ```

5. Initialize database
   ```
   python seed.py
   ```

6. Run application
   ```
   python run.py
   ```

Access at `http://localhost:5000`

## Test Credentials

After seeding the database:
- analyst1 / analyst1pass (Level 1)
- analyst2 / analyst2pass (Level 2)
- admin / adminpass (Administrator)

## Key Features

**Threat Feed Aggregation**: Automatically fetches and parses RSS feeds from security news sources every 30 minutes.

**Role-Based Access Control**: Three user roles (Level 1 Analyst, Level 2 Analyst, Administrator) with different permission levels and data visibility.

**IOC Extraction**: Google Gemini API analyzes article content to extract Indicators of Compromise (IP addresses, domains, file hashes).

**MITRE ATT&CK Mapping**: Threat techniques are mapped to MITRE ATT&CK framework for better threat classification.

**Vulnerability Tracking**: Integrates CISA KEV data with EPSS scores to track exploitable vulnerabilities.

**JWT Authentication**: API endpoints secured with Bearer token authentication for programmatic access.

## Database Design

**User Table**
- username (unique)
- password_hash (bcrypt)
- role (analyst_l1, analyst_l2, admin)
- clearance level
- last_login timestamp

**NewsArticle Table**
- title, source, URL
- published_at timestamp
- category (Vulnerability, Breach, Threat Actor, etc.)
- severity (Critical, High, Medium, Low)
- summary
- cve_id, epss_score
- iocs_extracted (JSON array)
- mitre_techniques (JSON array)
- ai_processed flag

## API Endpoints

```
POST   /api/auth/login              - User login
GET    /api/articles                - Fetch articles with filtering
GET    /api/articles/<id>           - Get single article
PATCH  /api/articles/<id>           - Update article notes
POST   /api/auth/logout             - User logout
```

All endpoints require Bearer token authentication.

## Configuration

The project supports three environments:

- Development: Debug mode enabled, SQLite database, insecure cookies
- Production: Debug disabled, PostgreSQL database, secure HTTPS cookies
- Testing: In-memory SQLite, CSRF disabled

Configure via `FLASK_ENV` environment variable.

## Background Jobs

APScheduler runs RSS feed collection every 30 minutes:
1. Fetches articles from configured feed sources
2. Deduplicates articles by URL
3. Stores new articles in database
4. Queues articles for AI processing (max 10 per run)

Gemini AI processes unprocessed articles to extract IOCs and map MITRE techniques.

## Learning Objectives

This project demonstrates:
- Secure password hashing with bcrypt
- JWT token-based API authentication
- Role-based access control implementation
- Threat intelligence data modeling
- Background job scheduling
- Third-party API integration (RSS, Gemini)
- Database query optimization
- SQL injection prevention with ORM
- Session security configuration

## License

MIT License
