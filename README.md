# NGShield - Real-Time DNS Monitoring & Threat Detection for Nigerian Domains

## 1. Project Title and Theme

**Project Name:** NGShield  
**Hackathon Theme:** Cybersecurity & Registry Efficiency for the Nigerian TLD Ecosystem

NGShield addresses the critical cybersecurity needs of organizations managing Nigerian (.ng) domains by providing real-time DNS monitoring, unauthorized access detection, and comprehensive threat analytics tailored to the NiRA ecosystem.

---

## 2. Problem Statement

### The Challenge
Nigerian organizations face significant cybersecurity threats targeting their domain infrastructure, yet lack affordable, purpose-built solutions for DNS monitoring and threat detection. Common challenges include:

- **DNS Hijacking & Unauthorized Changes:** Attackers exploit weak domain controls to redirect traffic and compromise services
- **Lack of Real-Time Visibility:** Organizations have no clear alerting when their DNS records are modified
- **Compliance & Audit Gaps:** Limited audit trails and change logs for compliance requirements
- **Adult Content Blocking:** Schools, workplaces, and family networks need effective content filtering
- **Extension-Based Protection:** Limited browser-level protection for accessing potentially dangerous sites

### Why It's Relevant to NiRA
The Nigerian domain registry (NiRA) serves thousands of organizations that require robust security infrastructure. Without purpose-built tools, these organizations:
- Lose business continuity when DNS attacks occur
- Face regulatory compliance challenges
- Lack forensic capabilities for incident response
- Cannot effectively protect their digital presence

NGShield fills this gap by providing a dedicated, affordable platform designed specifically for .ng domain security.

---

## 3. Solution & Implementation

### High-Level Architecture

NGShield is a full-stack web application combining Django backend, Tailwind CSS frontend, and browser extension technology to deliver comprehensive DNS security.

```
┌─────────────────────────────────────────────────────────────┐
│                    NGShield Platform                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │  Browser         │  │  Dashboard       │                 │
│  │  Extension       │  │  (Web UI)        │                 │
│  │  (Chrome/Brave)  │  │                  │                 │
│  └────────┬─────────┘  └────────┬─────────┘                 │
│           │                     │                            │
│           │    Reports Blocks   │  Manages Settings          │
│           └────────────┬────────┘                            │
│                        │                                      │
│           ┌────────────▼──────────────┐                      │
│           │   Django REST API         │                      │
│           │  (/api/extension/*)       │                      │
│           │  (/api/domain/*)          │                      │
│           │  (/api/alerts/*)          │                      │
│           └────────────┬──────────────┘                      │
│                        │                                      │
│           ┌────────────▼──────────────┐                      │
│           │   PostgreSQL Database     │                      │
│           │  - Domains                │                      │
│           │  - ScanEvents             │                      │
│           │  - ThreatAlerts           │                      │
│           │  - AdultContentDomains    │                      │
│           │  - BlockedURLs            │                      │
│           └───────────────────────────┘                      │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Core Features & Technologies

#### 1. **Real-Time DNS Monitoring**
- **Technology:** Django + dnspython + WHOIS API
- **Functionality:** 
  - Continuous monitoring of DNS records (A, AAAA, CNAME, MX, TXT, NS)
  - Change detection with timestamped audit logs
  - WHOIS information retrieval for domain analysis
  - Historical DNS record tracking


#### 2. **Browser Extension for Content Blocking**
- **Technology:** Chrome/Brave Manifest V3 Extension + JavaScript
- **Functionality:**
  - Real-time URL filtering using AdultContentDomain blocklist
  - Automatic blocking of adult content and malware domains
  - User-friendly blocked page with reporting mechanism
  - Background service worker for efficient filtering
  - Automatic blocklist synchronization from server

#### 3. **Adult Content Blocking Dashboard**
- **Technology:** Django views + Tailwind CSS + Fetch API
- **Functionality:**
  - Dashboard-based domain blocklist management
  - Category-based organization (Pornography, Nudity, Adult Dating, Illegal Content, Malware, Spam)
  - One-click add/delete operations
  - Real-time blocklist updates to extension


#### 4. **Analytics & Reporting**
- **Technology:** Chart.js + Django aggregations
- **Functionality:**
  - DNS change history visualization
  - Domain monitoring statistics
  - Rescan count tracking
  - Threat timeline analytics
  - PDF report generation

### API Endpoints

```
Authentication:
  POST   /auth/register/           - User registration
  POST   /auth/login/              - User login
  GET    /auth/logout/             - User logout

Domain Management:
  GET    /api/domains/             - List user's domains
  POST   /api/add-domain/          - Add new domain
  GET    /api/domain/<id>/         - Get domain details
  POST   /api/domain/delete/       - Delete domain
  POST   /api/domain/<id>/rescan/  - Manually rescan domain

DNS & Monitoring:
  GET    /api/check-domain-status/ - Fetch DNS records & WHOIS
  GET    /api/change-history/      - Get DNS change history

Adult Blocklist Management:
  GET    /api/extension/adult-blocklist/   - Fetch blocklist for extension
  POST   /api/adult-domain/add/            - Add domain to blocklist
  POST   /api/adult-domain/delete/         - Remove from blocklist

Threat & Alerts:
  GET    /api/alerts/                      - List alerts
  POST   /api/extension/report-blocked-attempt/ - Report blocked access
  POST   /api/alert/<id>/resolve/          - Mark alert resolved

Browser Extension:
  GET    /api/extension/check-url/         - Check if URL is blocked
  POST   /api/extension/report-ad/         - Report ad attempt
```

### Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Backend** | Django 4.x, Python 3.13, PostgreSQL |
| **Frontend** | HTML5, Tailwind CSS, Chart.js, Vanilla JavaScript |
| **Extension** | Chrome/Brave Manifest V3, Service Workers |
| **DevOps** | Docker, GitHub Actions, Gunicorn, Nginx |
| **Security** | CSRF tokens, Session auth, Password hashing, HTTPS |

---

## 4. Future Roadmap

### Phase 1: Enhanced Analytics & Intelligence (Months 1-2)
- **Advanced Threat Intelligence:** Integration with VirusTotal, URLhaus APIs for malware detection
- **Predictive Alerts:** Machine learning models to detect suspicious patterns before attacks occur
- **Custom Reporting:** Exportable threat reports in PDF/CSV formats with executive summaries

### Phase 2: Enterprise Features & Scalability (Months 3-4)
- **Multi-Tenant Support:** Organizations manage multiple domains with team collaboration
- **API Rate Limiting & Monetization:** Tiered API access with subscription models
- **SSO Integration:** LDAP/SAML integration for enterprise authentication
- **Slack/Teams Integration:** Direct alerts to communication platforms

### Phase 3: Global Expansion & Monetization (Months 5-6)
- **Multi-TLD Support:** Extend beyond .ng to other African TLDs (.za, .ke, .gh)
- **Premium Tier:** Advanced features (24/7 support, custom integrations, dedicated infrastructure)
- **Enterprise Licensing:** Per-domain licensing model with volume discounts
- **Managed Services:** Offer DNS security as a managed service for small businesses

### Phase 4: Community & Ecosystem (Ongoing)
- **Open Blocklist Registry:** Community-curated blocklists for adult content and malware
- **NiRA Partnership:** Official partnership with Nigerian Registry to embed security recommendations
- **Educational Resources:** Training materials for organizations on DNS security best practices
- **Threat Sharing Network:** Anonymous threat intelligence sharing among users

## 5. Team Member Contributions

### Development Team

**NAME: Antem Joshua**
- **Role:** Backend Engineer/Extension Builder



**NAME: Oluwawumi Samue**
- **Role:** Frontend Developer/UI Design

