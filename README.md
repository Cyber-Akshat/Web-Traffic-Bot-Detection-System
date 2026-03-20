# Web Traffic Bot Detection & Monitoring System

## Overview
This project is a **cybersecurity-focused web traffic monitoring system** designed to detect and analyse suspicious bot activity in real time.

It simulates how a **Security Operations Center (SOC)** identifies automated threats such as:
- Brute-force login attempts  
- Web scraping bots  
- High-frequency automated requests  

The system monitors incoming traffic, applies detection rules, logs activity, and flags potentially malicious behaviour.

---

## Objectives
- Detect abnormal web traffic patterns  
- Identify automated/bot behaviour  
- Simulate real-world SOC monitoring  
- Provide basic threat analysis and logging  

---

##  Technologies Used
- **Python**
- **Flask** (web framework)
- **Logging system (custom / file-based)**
- Basic networking concepts

---

##  How It Works

### 1. Traffic Monitoring
The system captures incoming requests and extracts:
- IP address  
- Timestamp  
- Request frequency  
- User-Agent  

---

### 2. Detection Techniques

####  Rate Limiting
- Flags IPs sending excessive requests in a short time  
- Example: 100+ requests per minute  

####  User-Agent Analysis
- Detects:
  - Empty user-agents  
  - Suspicious or known bot signatures  

####  Behavioural Patterns
- Repeated access patterns  
- Rapid endpoint requests  

---

### 3. Logging System
All activity is recorded, including:
- IP address  
- Request count  
- Detection status (Normal / Suspicious / Bot)  
- Timestamp  

---

### 4. Alert Mechanism
When suspicious behaviour is detected:
- The system flags the IP  
- Generates a warning/alert  

---

##  Example Detection Scenario

### Scenario: Brute-Force Simulation

```
IP: 192.168.1.25
Requests: 140 requests/min
User-Agent: Python-Requests/2.31

Status:  FLAGGED AS BOT
Reason: Excessive request rate + automated user-agent
```

---

##  Sample Log Output

```
[2026-03-20 14:22:10] IP: 192.168.1.25 | Requests: 140 | Status: BOT DETECTED
[2026-03-20 14:22:35] IP: 192.168.1.10 | Requests: 12 | Status: NORMAL
```

---

##  Security Analysis

This system demonstrates key cybersecurity concepts used in real-world environments:

- **Rate-based detection** → Identifies brute-force and DDoS-like behaviour  
- **User-Agent inspection** → Detects automated tools/scripts  
- **Traffic monitoring** → Mimics SOC-level log analysis  
- **Threat identification** → Differentiates between normal and malicious traffic  

---

##  Real-World Applications
- Web application protection  
- Intrusion detection systems (IDS)  
- Security monitoring in SOC environments  
- API abuse prevention  

---

##  Future Improvements
- Integration with a database (e.g. SQLite)  
- Visual dashboard for monitoring  
- Machine learning-based detection  
- IP blocking / firewall integration  
- Integration with SIEM tools (e.g. Splunk)

---

##  Project Structure
```
Bot-Detector/
│── app.py
│── logs/
│── templates/
│── static/
│── README.md
```

---


##  Author
**Akshat**  
Aspiring Cybersecurity Analyst  
