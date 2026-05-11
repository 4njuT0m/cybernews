"""
seed.py — Populate the database with initial users and mock articles.
Safe to run multiple times (idempotent).

Usage:
    python seed.py
    FLASK_ENV=production python seed.py
"""
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

import bcrypt

USERS = [
    {"username": "analyst1", "password": "analyst1pass",
     "role": "analyst_l1", "display_name": "J. Carter",  "clearance": "Level 1 Analyst"},
    {"username": "analyst2", "password": "analyst2pass",
     "role": "analyst_l2", "display_name": "S. Novak",   "clearance": "Level 2 Analyst"},
    {"username": "admin",    "password": "adminpass",
     "role": "admin",       "display_name": "R. Voss",    "clearance": "Administrator"},
]

INITIAL_ARTICLES = [
    {
        "title": "Critical CVE-2024-6387 in OpenSSH — Unauthenticated RCE as Root",
        "source": "The Hacker News",
        "url": "https://thehackernews.com/2024/07/openssh-regresshion.html",
        "category": "Vulnerability", "severity": "Critical",
        "summary": "A regression vulnerability dubbed regreSSHion affects OpenSSH servers on glibc-based Linux systems, enabling unauthenticated RCE as root. CVSS 9.8. Patch to 9.8p1 immediately.",
        "cve_id": "CVE-2024-6387", "epss_score": 0.94,
        "internal_ip": "10.42.0.11", "internal_note": "Affects 3 DMZ prod servers — ticket INC-4821",
    },
    {
        "title": "LockBit 3.0 Claims 2TB Breach of Major European Bank",
        "source": "SecurityWeek",
        "url": "https://www.securityweek.com/lockbit-bank-breach-2025",
        "category": "Breach", "severity": "Critical",
        "summary": "LockBit 3.0 claims exfiltration of 2TB including IBAN numbers and executive communications from a Tier-1 European bank.",
        "internal_ip": "192.168.5.200", "internal_note": "No confirmed client data. Monitoring dark web mirrors.",
    },
    {
        "title": "CISA Adds 5 New Entries to Known Exploited Vulnerabilities Catalog",
        "source": "CISA",
        "url": "https://www.cisa.gov/news-events/alerts/2025/05/06/kev-update",
        "category": "Advisory", "severity": "High",
        "summary": "Five new Known Exploited Vulnerabilities added. Federal agencies have 21 days to patch under BOD 22-01.",
        "cve_id": "CVE-2025-0282", "epss_score": 0.78,
        "internal_ip": "10.0.0.50", "internal_note": "Cisco IOS XE border router — patching Saturday.",
    },
    {
        "title": "Lazarus Group Deploys Updated BLINDINGCAN RAT Against Crypto Exchanges",
        "source": "The Hacker News",
        "url": "https://thehackernews.com/2025/05/lazarus-blindingcan.html",
        "category": "Threat Actor", "severity": "High",
        "summary": "North Korean APT Lazarus Group uses process hollowing and encrypted C2 channels to target cryptocurrency exchanges across Southeast Asia.",
        "internal_ip": "172.16.4.88", "internal_note": "IOCs added to SIEM block list 05/05.",
    },
    {
        "title": "Microsoft Patch Tuesday May 2025 — 78 CVEs Fixed, 6 Critical",
        "source": "SecurityWeek",
        "url": "https://www.securityweek.com/patch-tuesday-may-2025",
        "category": "Patch", "severity": "High",
        "summary": "May Patch Tuesday covers 78 CVEs including 6 critical flaws in Windows LDAP, Exchange, and Azure DevOps. Three actively exploited in the wild.",
        "internal_ip": "10.1.0.5", "internal_note": "DC patching scheduled next maintenance window.",
    },
    {
        "title": "Supply Chain Attack Discovered in npm Package with 2M Weekly Downloads",
        "source": "The Hacker News",
        "url": "https://thehackernews.com/2025/05/npm-supply-chain.html",
        "category": "Supply Chain", "severity": "Critical",
        "summary": "The polyfill.io npm package was found to contain a backdoor injected after a malicious acquisition, exfiltrating environment variables from 2M weekly users.",
        "internal_ip": "10.50.3.22", "internal_note": "Package removed from all repos. Audit underway.",
    },
    {
        "title": "Iranian APT MuddyWater Deploys BugSleep Backdoor via Spear-Phishing",
        "source": "SecurityWeek",
        "url": "https://www.securityweek.com/muddywater-bugsleep-2025",
        "category": "Threat Actor", "severity": "Medium",
        "summary": "MuddyWater (TA450) delivers a new backdoor BugSleep via spear-phishing lures mimicking SaaS onboarding emails. Targets government and critical infrastructure.",
        "internal_ip": "172.20.10.3", "internal_note": "Email gateway rules updated.",
    },
    {
        "title": "Critical Auth Bypass in Fortinet FortiOS — PoC Exploit Released",
        "source": "CISA",
        "url": "https://www.cisa.gov/fortinet-fortios-advisory-2025",
        "category": "Vulnerability", "severity": "Critical",
        "summary": "Public PoC for CVE-2024-21762 now circulating. Out-of-bounds write in FortiOS SSL VPN allows unauthenticated code execution.",
        "cve_id": "CVE-2024-21762", "epss_score": 0.97,
        "internal_ip": "10.99.1.254", "internal_note": "FortiOS perimeter FW version 7.2.4 — VULNERABLE. Emergency patch raised.",
    },
    {
        "title": "Volt Typhoon Maintained Covert Access to US Infrastructure for 5+ Years",
        "source": "The Hacker News",
        "url": "https://thehackernews.com/2025/04/volt-typhoon-infrastructure.html",
        "category": "Threat Actor", "severity": "Critical",
        "summary": "Joint CISA/NSA/FBI advisory reveals Volt Typhoon (China-nexus) maintained covert access to US water utilities and power grids for over five years using living-off-the-land techniques.",
        "internal_ip": "10.200.0.1", "internal_note": "Hunting query deployed in SIEM for LOTL indicators.",
    },
    {
        "title": "Black Basta Ransomware Now Using Microsoft Teams for Initial Access",
        "source": "SecurityWeek",
        "url": "https://www.securityweek.com/black-basta-teams-2025",
        "category": "Malware", "severity": "High",
        "summary": "Black Basta floods corporate Microsoft Teams with fake IT support messages to social-engineer employees into granting remote access via Quick Assist.",
        "internal_ip": "192.168.100.45", "internal_note": "Teams external message policy reviewed — guest access restricted.",
    },
    {
        "title": "Google Project Zero Discloses Zero-Day in Windows Kernel Memory Manager",
        "source": "The Hacker News",
        "url": "https://thehackernews.com/2025/05/windows-kernel-zero-day.html",
        "category": "Vulnerability", "severity": "High",
        "summary": "Google Project Zero publishes details of an unpatched zero-day in Windows kernel memory management enabling local privilege escalation. Fix expected next Patch Tuesday.",
        "internal_ip": "10.10.5.77", "internal_note": "Monitoring workstation fleet for exploitation attempts.",
    },
    {
        "title": "EPSS Model Update: 23 CVEs Now at >90% Exploitation Probability",
        "source": "CISA",
        "url": "https://www.cisa.gov/epss-update-may-2025",
        "category": "Advisory", "severity": "Medium",
        "summary": "EPSS update flags 23 newly disclosed CVEs with >90% exploitation probability, including flaws in Palo Alto PAN-OS, VMware vCenter, and Linux kernel.",
        "internal_ip": "10.0.1.33", "internal_note": "vCenter version check in progress.",
    },
]


def seed(app):
    from app import db
    from app.models import User, NewsArticle
    from datetime import datetime

    with app.app_context():
        db.create_all()

        # ── Users ──────────────────────────────────────────────────────────
        print("\n[ Seeding Users ]")
        users_created = 0
        for u in USERS:
            if User.query.filter_by(username=u["username"]).first():
                print(f"  SKIP  {u['username']} — already exists")
                continue
            pw_hash = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
            db.session.add(User(
                username=u["username"], password_hash=pw_hash,
                role=u["role"], display_name=u["display_name"],
                clearance=u["clearance"],
            ))
            users_created += 1
            print(f"  OK    {u['username']} ({u['role']})")
        db.session.commit()
        print(f"  → {users_created} new users created")

        # ── Articles ───────────────────────────────────────────────────────
        print("\n[ Seeding Articles ]")
        articles_created = 0
        from datetime import timedelta
        base_date = datetime.utcnow()
        for i, a in enumerate(INITIAL_ARTICLES):
            if NewsArticle.query.filter_by(url=a["url"]).first():
                print(f"  SKIP  {a['title'][:50]}...")
                continue
            article = NewsArticle(
                title         = a["title"],
                source        = a["source"],
                url           = a["url"],
                published_at  = base_date - timedelta(hours=i * 8),
                category      = a["category"],
                severity      = a["severity"],
                summary       = a["summary"],
                cve_id        = a.get("cve_id"),
                epss_score    = a.get("epss_score"),
                internal_ip   = a.get("internal_ip", ""),
                internal_note = a.get("internal_note", ""),
                ai_processed  = False,
            )
            db.session.add(article)
            articles_created += 1
            print(f"  OK    {a['title'][:60]}")
        db.session.commit()
        print(f"  → {articles_created} new articles created")

        print("\n✓ Seed complete\n")
        print("Test credentials:")
        print("  analyst1 / analyst1pass  (Level 1 Analyst)")
        print("  analyst2 / analyst2pass  (Level 2 Analyst)")
        print("  admin    / adminpass     (Administrator)")


if __name__ == "__main__":
    from app import create_app
    app = create_app(os.environ.get("FLASK_ENV", "development"))
    seed(app)