# 🛡️ RDP Lateral Movement Detection (Splunk ES | MITRE T1021.001)

> Detects possible RDP-based lateral movement when the same user logs into 2 or more different hosts within a 5-minute window using Logon Type 10 (Remote Desktop Protocol).

---

## 🧠 Overview

This detection project identifies **RDP-based lateral movement attempts** within a Windows environment. It raises a notable event when the **same user logs into 2 or more different hosts via RDP (Logon Type 10)** within a **5-minute window** — a common post-compromise technique used by attackers to move laterally across systems.

Implemented from scratch in **Splunk Enterprise Security**, the project involved end-to-end steps including **RDP log validation**, **SPL writing**, **correlation rule setup**, and **manual triage**. Although the correlation rule didn't trigger during the live run, it successfully detected historic activity demonstrating detection logic accuracy.

---

## 🎯 Objective

* Detect early signs of **lateral movement** within internal infrastructure.
* Generate alerts in Splunk ES when RDP logons by the same user occur on 2+ hosts in a short window.
* Mitigate risk from credential misuse, insider threats, or unauthorized privilege escalation.
* Practice false-positive validation using real logs from a lab setup.

---

## 🔧 Tools & Technologies Used

| Tool                             | Purpose                                          |
| -------------------------------- | ------------------------------------------------ |
| Splunk Enterprise Security       | Detection engineering, correlation, alerting     |
| SPL (Search Processing Language) | Querying Windows Security logs                   |
| Windows Event Logs               | Log source for EventCode 4624 (successful logon) |
| MITRE ATT\&CK                    | Mapping to adversary techniques (T1021.001)      |

---

## 📊 Log Source Information

| Field       | Value                                                     |
| ----------- | --------------------------------------------------------- |
| Index       | `main`                                                    |
| Hosts       | `WIN-1-2MEFU6AR0Q2`, `WIN-2MEFU6AR0Q2`, `WIN-5EJCIO9KVIB` |
| Sourcetype  | `WMI:WinEventLog:Security`                                |
| EventCode   | `4624` – Successful logon                                 |
| Logon\_Type | `10` – Remote Desktop Protocol (RDP)                      |

---

## ✅ Project Execution Flow

### 1️⃣ RDP Log Validation

We verified whether **RDP login (Logon Type 10)** events were actively ingested into the environment.

```spl
index=main sourcetype="WMI:WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count by Account_Name, host, ComputerName, Logon_Type, _time
```

✅ Result: Over **35 events** detected, confirming RDP log visibility.

📸 **Screenshot:** `screenshots/1_rdp_raw_log_check.png`

---

### 2️⃣ SPL-Based Detection Logic

The detection logic identifies users logging into **2+ different hosts** via RDP within a **5-minute window**.

```spl
index=main sourcetype="WMI:WinEventLog:Security" EventCode=4624 Logon_Type=10
| eval logon_time = _time
| bucket _time span=5m
| stats dc(host) as dest_count values(host) as dest_host min(logon_time) as first_time max(logon_time) as last_time by Account_Name, _time
| where dest_count >= 2
| eval comment="Same user logged into multiple hosts via RDP within 5 minutes - possible lateral movement"
```

📘 **SPL Breakdown:**

| Command                       | Description                                 |
| ----------------------------- | ------------------------------------------- |
| EventCode=4624 Logon\_Type=10 | Filters successful RDP logins               |
| bucket \_time span=5m         | Groups logins into 5-minute windows         |
| dc(host)                      | Counts distinct hosts per user              |
| where dest\_count >= 2        | Flags cases with lateral movement potential |
| comment=...                   | Adds context to support triage              |

📸 **Screenshot:** `screenshots/2_spl_query_output.png`

---

### 3️⃣ Sample Detection Output

```
Account_Name: Administrator  
dest_count: 2  
dest_host: WIN-1-2MEFU6AR0Q2, WIN-2MEFU6AR0Q2  
first_time: 2025-xx-xx 11:25:00  
comment: Same user logged into multiple hosts via RDP within 5 minutes
```

🔍 Status: **False positive**. Confirmed as part of legitimate administrator activity.

---

## ⚙️ Correlation Rule Configuration (Splunk ES)

| Field             | Value                                     |
| ----------------- | ----------------------------------------- |
| Search Name       | `rdp_lateral_movement_detection`          |
| App               | Enterprise Security                       |
| Schedule          | `*/5 * * * *` (Every 5 minutes)           |
| Time Range        | `-24h` to `now`                           |
| Trigger Condition | If results > 0                            |
| Trigger Mode      | Real-time                                 |
| Severity          | High                                      |
| Kill Chain Phase  | Lateral Movement                          |
| Security Domain   | Threat                                    |
| MITRE Technique   | T1021.001 – Remote Desktop Protocol       |
| CIS Control       | Control 9: Limitation of Network Services |
| NIST              | PR.DS-5 – Unauthorized access protection  |

📸 **Screenshot:** `screenshots/3_correlation_rule_config.png`

---

## 🚨 Notable Event Configuration

* **Title:**
  `Possible RDP Lateral Movement by $Account_Name$`

* **Description:**
  `User $Account_Name$ logged into multiple hosts via RDP within a 5-minute window. Possible lateral movement.`

* **Drill-down Search:**

```spl
index=main sourcetype="WMI:WinEventLog:Security" EventCode=4624 Logon_Type=10 Account_Name="$Account_Name$"
```

📸 **Screenshot:** `screenshots/4_notable_event_config.png`

---

## 🔁 Content Management Rule Listing

📸 **Screenshot:** `screenshots/5_rule_listed_content_mgmt.png`

---

## 📊 MITRE ATT\&CK Mapping

| Field     | Value                                                     |
| --------- | --------------------------------------------------------- |
| Tactic    | Lateral Movement                                          |
| Technique | T1021.001 – Remote Desktop Protocol                       |
| Summary   | Adversaries may use RDP to move laterally post-compromise |

---

## 🖼️ Screenshot Reference Table

| Stage                          | Screenshot File                               |
| ------------------------------ | --------------------------------------------- |
| RDP raw log check              | `screenshots/1_rdp_raw_log_check.png`         |
| SPL output - detection         | `screenshots/2_spl_query_output.png`          |
| Correlation rule configuration | `screenshots/3_correlation_rule_config.png`   |
| Notable event configuration    | `screenshots/4_notable_event_config.png`      |
| Rule listed in Content Mgmt    | `screenshots/5_rule_listed_content_mgmt.png`  |
---

## 🎓 Learning Outcomes

✅ Gained hands-on experience in detecting RDP-based lateral movement using real Windows log data.  
✅ Mastered the use of SPL commands like bucket, dc(), and time-window grouping for correlation logic.  
✅ Learned to identify and interpret Logon_Type=10 within EventCode 4624 for RDP session detection.  
✅ Designed, configured, and tested correlation rules and drill-downs in Splunk ES.  
✅ Practiced end-to-end SOC workflows: log validation → detection logic → alert creation → analyst triage → outcome classification.  
✅ Strengthened ability to differentiate between legitimate admin behavior and potential threats

---

## ✍️ Author

**Rahul Krishna R**    
Defensive Security Practitioner | Hands-on with SOC, Threat Detection & Cryptography   
This project is part of my practical cybersecurity portfolio, built to simulate real-world SOC use cases using Splunk.

---
