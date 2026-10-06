# 🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard

A defensive cybersecurity dashboard built with Python and Streamlit for analyzing threat intelligence, Indicators of Compromise (IOCs), security alerts, vulnerabilities, MITRE ATT&CK techniques, threat trends, and cybersecurity awareness.

---

## 📌 Project Overview

The Cybersecurity Awareness & Threat Intelligence Dashboard is an educational and defensive security application designed to provide a SOC-style interface for analyzing cybersecurity information.

The dashboard combines threat intelligence analysis with cybersecurity awareness features to help users understand:

- Threat indicators
- Threat severity
- Security alerts
- Threat categories
- MITRE ATT&CK techniques
- Vulnerability awareness
- Threat trends
- IOC risk
- Cybersecurity best practices
- Security awareness knowledge

The project uses local and synthetic/educational data and does not perform active scanning, exploitation, or interaction with suspicious external infrastructure.

---

## 🎯 Objectives

The main objectives of this project are:

1. Analyze cybersecurity threat intelligence records.
2. Identify and classify Indicators of Compromise.
3. Calculate threat risk using severity and confidence.
4. Analyze security alerts and threat states.
5. Map threats to MITRE ATT&CK techniques.
6. Provide vulnerability awareness.
7. Visualize threat trends and severity.
8. Provide SOC-style investigation capabilities.
9. Educate users about common cybersecurity threats.
10. Provide an interactive cybersecurity awareness quiz.
11. Generate an executive-level cybersecurity summary.

---

## 🚀 Key Features

### 🔍 Threat Intelligence

- Threat intelligence feed
- Threat category analysis
- Threat severity analysis
- Threat confidence analysis
- Threat search
- Threat filtering
- Threat trend analysis

### 🧩 IOC Analysis

Supports analysis of:

- IP addresses
- Domains
- URLs
- File hashes
- Email/sender domains
- CVE identifiers

IOC analysis is passive and local.

---

### 🚨 Security Alerts

The dashboard distinguishes between:

- OBSERVATION
- INDICATOR
- ALERT
- THREAT
- INCIDENT

This prevents every suspicious indicator from automatically being treated as a confirmed attack.

---

### 📊 Threat Risk Scoring

The system calculates a risk score using:

- Threat severity
- Confidence level

Risk levels include:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

### 🎯 MITRE ATT&CK Mapping

Threat intelligence records can be mapped to MITRE ATT&CK techniques.

Examples include:

- T1566 - Phishing
- T1078 - Valid Accounts
- T1110 - Brute Force
- T1190 - Exploit Public-Facing Application
- T1486 - Data Encrypted for Impact
- T1041 - Exfiltration Over C2 Channel

---

### 🛡️ Vulnerability Awareness

The dashboard provides educational vulnerability information including:

- CVE identifier
- Severity
- Affected component
- Description
- Potential impact
- Defensive recommendation

The included vulnerability records are fictional/local educational examples.

---

### 📈 Threat Visualization

The dashboard provides visual analysis of:

- Severity distribution
- Threat categories
- Security status
- Threat trends
- Indicator types

---

### 👨‍💻 SOC Investigation View

The SOC-style investigation section allows users to examine:

- Security alerts
- Indicator details
- Severity
- Confidence
- Risk score
- MITRE ATT&CK technique
- Observation date
- Source
- Description

---

### 🎓 Cybersecurity Awareness

The Awareness Learning Center provides educational content covering:

- Phishing
- Account Security
- Malware
- Ransomware
- Social Engineering
- Web Security
- Data Protection

Each topic contains warning signs and recommended security practices.

---

### 📝 Security Awareness Quiz

The dashboard includes an interactive cybersecurity awareness quiz.

The quiz provides:

- Questions
- Multiple-choice answers
- Score
- Percentage
- Awareness level
- Answer review

Awareness levels include:

- Excellent
- Good
- Developing
- Needs Improvement

---

### 📋 Executive Cybersecurity Summary

The executive summary provides high-level information including:

- Total threat records
- Unique indicators
- High/Critical records
- Alerts
- Threats
- Incidents
- Most common threat category
- Most common indicator type
- Overall risk posture
- Security recommendations

---

## 🏗️ Project Architecture

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard
│
├── app.py
│
├── data/
│   └── threat_intelligence.csv
│
├── src/
│   ├── data_loader.py
│   ├── ioc_analyzer.py
│   ├── threat_scoring.py
│   ├── mitre_mapping.py
│   ├── alert_engine.py
│   ├── awareness_content.py
│   ├── quiz_data.py
│   ├── executive_summary.py
│   ├── vulnerability_awareness.py
│   └── validators.py
│
├── .gitignore
├── requirements.txt
└── README.md