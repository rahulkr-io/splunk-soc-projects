# 🛡️ Successful Firewall Connection from Blacklisted IP (Threat Intel-based Detection)

> Detects and alerts on successful firewall connections **allowed from known blacklisted IP addresses**, indicating a critical potential security risk. Includes real-world threat enrichment using AbuseIPDB, Cisco Talos, and VirusTotal.

---

## 🎯 Overview

In this project, we designed and implemented a **threat intelligence-based correlation search** in **Splunk Enterprise Security (ES)** to detect allowed firewall traffic originating from **malicious IPs present in a custom blacklist**. These IPs were validated using external **Threat Intelligence (TI) platforms**, and we discovered successful **SSH and custom TCP port (4433)** connections from high-confidence malicious sources.

The goal was to simulate a **real-world SOC use case** involving:

- TI-based detection logic  
- Firewall log analysis  
- Correlation rule configuration  
- Manual IP enrichment  
- Alert triage and recommendations

---

## 🎯 Objectives

- Detect incoming allowed connections from blacklisted external IPs  
- Validate the threat using open-source TI platforms  
- Generate a real-time notable alert via Splunk ES  
- Practice a complete SOC L1 detection + triage workflow   

---

## 🔧 Tools & Technologies Used

| Tool / Platform             | Purpose                                              |
|----------------------------|------------------------------------------------------|
| **Splunk Enterprise Security** | SIEM detection, correlation rule, notable alerts |
| **SPL (Search Processing Language)** | Custom detection logic and filtering      |
| **Fortinet Firewall Logs** | Source of traffic events (sourcetype: fortigate_traffic) |
| **Threat Intelligence Feeds** | Blacklisted IP enrichment and validation          |
| AbuseIPDB, Cisco Talos, VirusTotal | Manual TI analysis and verification      |

---

## 📊 Log Source Information

| Attribute     | Value                                   |
|---------------|------------------------------------------|
| **Index**     | `main`                                  |
| **Sourcetype**| `fortigate_traffic`                     |
| **Action**    | `allowed`                               |
| **Fields Used** | `src`, `dest`, `dest_port`, `service`, `action` |

---

## 🧠 Detection Workflow

### 1. 🔧 Lookup Table Creation

A custom lookup file `blacklist_ips.csv` was created with known malicious IPs.

- 📸 [Create Lookup Table](./screenshots/lookup_creation/lookup_create.png)  
- 📸 [Verify Lookup via SPL](./screenshots/lookup_creation/lookup_verify_search.png)  
- 📸 [Set Permissions Global](./screenshots/lookup_creation/lookup_permission.png)  

```csv
src_ip
195.178.110.160
3.130.96.91
3.131.215.38
````

---

### 2. 🔍 SPL Query for Detection

```spl
index=main sourcetype=fortigate_traffic action=allowed
| where NOT (cidrmatch("10.0.0.0/8", src) OR cidrmatch("172.16.0.0/12", src) OR cidrmatch("192.168.0.0/16", src))
| lookup blacklist_ips.csv src_ip OUTPUT src_ip as blacklisted_ip
| search blacklisted_ip=*
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src, dest, dest_port, service, action, blacklisted_ip
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

* 📸 [Search Result - 24 Hours](./screenshots/spl_results/raw_query_24hours.png)
* 📸 [Search Result - 48 Hours](./screenshots/spl_results/raw_query_48hours.png)

---

### 3. ✅ Key Findings

| Blacklisted IP  | Destination (Masked) | Port | Service  | Total Events |
| --------------- | -------------------- | ---- | -------- | ------------ |
| 195.178.110.160 | xxx.xx.xxx.50       | 22   | SSH      | 135          |
| 3.130.96.91     | xxx.xx.xxx.50       | 22   | SSH      | 14           |
| 3.131.215.38    | xxx.xx.xxx.50      | 22   | SSH      | 6            |
| 3.131.215.38    | xxx.xx.xxx.50       | 4433 | tcp/4433 | 6            |

* 📸 [Search Result - 7 Days](./screenshots/spl_results/raw_query_7days.png)

---

## 🧠 Correlation Rule Configuration

| Field               | Value                                                                |
| ------------------- | -------------------------------------------------------------------- |
| **Name**            | Allowed Firewall Connection from Blacklisted IP (TI-Based Detection) |
| **App**             | Enterprise Security                                                  |
| **Search Time**     | `-5m to now`                                                         |
| **Schedule**        | Every 5 minutes (`*/5 * * * *`)                                      |
| **Trigger**         | When number of results > 0                                           |
| **Severity**        | High                                                                 |
| **Security Domain** | Threat                                                               |
| **MITRE ATT\&CK**   | T1046 – Network Service Scanning, T1071 – Application Layer Protocol |

* 📸 [Correlation Rule Form](./screenshots/correlation_rule/correlation_rule_conf.png)
* 📸 [Notable Event Setup](./screenshots/correlation_rule/notable_conf.png)
* 📸 [Rule in Content List](./screenshots/correlation_rule/rule_listed_content_mgmt.png)

---

## 🌐 Threat Intelligence Enrichment

To validate the malicious nature of the blacklisted IPs that were successfully allowed through the firewall, we manually enriched each IP using:

* [AbuseIPDB](https://abuseipdb.com)
* [Cisco Talos Intelligence](https://talosintelligence.com)
* [VirusTotal](https://virustotal.com)

| Blacklisted IP      | AbuseIPDB Reports                                  | Talos Reputation                           | VirusTotal (Vendors Flagged)       | Verdict              |
| ------------------- | -------------------------------------------------- | ------------------------------------------ | ---------------------------------- | -------------------- |
| **195.178.110.160** | 34,039 reports, 100% confidence, Netherlands       | Untrusted, SBL listed                      | 9/94 (ArcSight, CyRadar, etc.)     | **Highly Malicious** |
| **3.130.96.91**     | 3,119 reports, 100% confidence, scan.cypex.ai      | Untrusted, on Talos blocklist              | 10/94 (Fortinet, MalwareURL, etc.) | **Malicious**        |
| **3.131.215.38**    | 2,312 reports, 100% confidence, AWS infrastructure | Poor reputation, suspicious classification | 8/94 (Fortinet, PhishTank, etc.)   | **Suspicious**       |

* 📸 [Threat Intel Screenshots](./screenshots/threat_intel_enrichment/)

---

## 🛡️ SOC Analyst Actions

Following the detection of allowed firewall traffic from known blacklisted IPs, the following analyst-level recommendations are proposed for escalation and remediation:

🔍 Investigate the Destination Host (dest)  
Perform endpoint triage on the internal asset that received traffic. Look for:

* SSH login activity

* Service exploitation or abnormal behavior

* Unexpected processes or user sessions

🔒 Block Malicious IPs at the Perimeter   
Immediately add the confirmed blacklisted IPs to the firewall blocklist. Where possible, integrate dynamic threat feeds to update this list in real-time.

🕵️ Review Historical Activity (Threat Hunting)     
Analyze past logs (7–30 days) for any:

* Repeated attempts from the same IPs

* Similar activity targeting other internal hosts or ports

* Lateral movement attempts or privilege escalations

⚙️ Evaluate Exposed Services and Authentication Methods   

* Enforce SSH key-based authentication if password login is enabled.

* Review services running on non-standard ports like TCP/4433.

* Validate firewall rules to restrict external access only to essential services.


---


## 📁 Files Included

| File Name                    | Purpose                                    |
| ---------------------------- | ------------------------------------------ |
| `blacklist_ips.csv`          | Custom TI list with malicious IPs          |
| `correlation_search_spl.txt` | Full correlation SPL used in the detection |

---

## 🧠 Learning Outcomes

✅ Built a real-world TI-based detection pipeline from scratch     
✅ Created and validated a lookup table (blacklist_ips.csv) with proper permissions for global access.   
✅ Wrote effective SPL queries using cidrmatch() to exclude internal IP ranges and match blacklisted source IPs.    
✅ Practiced raw log filtering, correlation, and event investigation.        
✅ Manually enriched threat data using AbuseIPDB, Cisco Talos, and VirusTotal to validate IP reputation.   
✅ Analyzed real-world traffic to identify multiple allowed SSH and TCP connections from confirmed malicious IPs.   
✅ Created real-time alerts with appropriate severity and MITRE mapping      
✅ Gained visibility into high-risk perimeter traffic hitting internal assets    

---

## ✍️ Author

**Rahul Krishna R**    
Defensive Security Practitioner | Hands-on with SOC, Threat Detection & Cryptography   
This project is part of my practical cybersecurity portfolio, built to simulate real-world SOC use cases using Splunk.

---
