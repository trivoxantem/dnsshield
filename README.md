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

NGShield is a full-stack web application combining Django backend, Tailwind CSS frontend, and browser extension technology to deliver comprehensive DNS security.

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
 
**Testing and Usage**
NGShield provides **two layers of protection - on 2 seperate browser you can use Firefox and Chrome, or Brave and Chrome**:


### 🟦 1. Network-Level Protection  (Open Browser A)
✔ Custom DNS server  
✔ Blocking of malicious domains  
✔ Real-time DNS monitoring  

### 🟩 2. Browser-Level Protection  (Open Browser B)
✔ Lightweight browser extension  
✔ URL scanning  
✔ Warning pop-ups  
✔ Real-time block system

### 🟩To test the application on Laptop you must have python installed or open the CMD and type "pip install -r requirements.txt" to insall everything and then open the project and in your Terminal in Visual STudio Code you will type "py manage.py runserver" and the port will be open locally on "http://127.0.0.1:8000"


### Technology Stack

| Layer | Technologies |
|-------|--------------|
| **Backend** | Django 4.x, Python 3.13, PostgreSQL |
| **Frontend** | HTML5, Tailwind CSS, Chart.js, Vanilla JavaScript |
| **Extension** | Chrome/Brave Manifest V3, Service Workers |
| **DevOps** | Docker, GitHub Actions, Gunicorn, Nginx |
| **Security** | CSRF tokens, Session auth, Password hashing, HTTPS |


## 5. Team Member Contributions

### Development Team

**NAME: Antem Joshua**
- **Role:** Backend Engineer/Extension Builder



**NAME: Oluwawumi Samue**
- **Role:** Frontend Developer/UI Design





