# 🛡️ Project 2: Brute Force Attack Detection with Success Correlation (Splunk ES | MITRE T1110)

> Detects a potential account compromise by identifying multiple failed login attempts (brute force) followed by a successful login.

---

## 🎯 Objective

To detect a brute-force attack scenario where an attacker attempts multiple failed logins (EventCode=4625) followed by a successful login (EventCode=4624), which may indicate credential compromise.

Implemented end-to-end detection using **Splunk Enterprise Security (ES)** with both **raw event-based SPL queries** and **CIM-compliant Authentication data model**, followed by **correlation rule creation** and **notable event alerting**.

---

## 🔧 Tools & Technologies Used

| Tool                             | Purpose                                       |
| -------------------------------- | --------------------------------------------- |
| Splunk Enterprise Security       | Detection engineering, correlation, alerting  |
| SPL (Search Processing Language) | Querying Windows logs and data models         |
| Windows Security Logs            | EventCode 4625 (failure), 4624 (success)      |
| MITRE ATT&CK                     | Framework mapping - T1110 (Brute Force)       |

---

## 📊 Log Source Information

| Field       | Values                                                                   |
| ----------- | ------------------------------------------------------------------------ |
| Index       | `main`                                                                   |
| Hosts       | `192.168.0.1`, `WIN-1-2MEFU6AR0Q2`, `WIN-2MEFU6AR0Q2`, `WIN-5EJCIO9KVIB` |
| Sourcetypes | `WMI:WinEventLog:Security`, `XmlWinEventLog:Security`                    |

---

## 🔍 Raw Log Based SPL Queries

### 🔹 Failed Login Detection
```spl
index=main sourcetype="WMI:WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security" EventCode=4625
| stats count as failed_count by Account_Name, src, dest
| where failed_count >= 5
````

### 🔹 Successful Login Detection

```spl
index=main sourcetype="WMI:WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security" EventCode=4624
| stats earliest(_time) as success_time by Account_Name, src, dest
```

### 🔹 Combined Correlation (Raw Log Based)

```spl
index=main sourcetype="WMI:WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security" EventCode=4625
| stats count as failed_count by Account_Name, src, dest
| where failed_count >= 5
| append [
    search index=main sourcetype="WMI:WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security" EventCode=4624
    | stats earliest(_time) as success_time by Account_Name, src, dest
]
| stats values(failed_count) as failed_count, values(success_time) as success_time by Account_Name, src, dest
| where isnotnull(failed_count)
```

---

## 🌐 Data Model Based SPL Query

### 🔹 Combined Correlation (Authentication Data Model)

```spl
| tstats `summariesonly` count as failed_count 
  from datamodel=Authentication 
  where Authentication.action="failure"
  by Authentication.user, Authentication.src, Authentication.dest
| where failed_count >= 5
| append [
    | tstats `summariesonly` earliest(_time) as success_time 
      from datamodel=Authentication 
      where Authentication.action="success"
      by Authentication.user, Authentication.src, Authentication.dest
]
| stats values(failed_count) as failed_count, values(success_time) as success_time by Authentication.user, Authentication.src, Authentication.dest
| where isnotnull(failed_count)
```

---

## 🧠 Correlation Rule Configuration (Splunk ES)

* **Search Name**: `Brute Force Login Attempts – Success Correlation (Data Model)`
* **App**: `Enterprise Security`
* **Schedule**: `*/5 * * * *` (Every 5 minutes)
* **Time Range**: `-10m` to `now`
* **Trigger Condition**: `> 0 results`
* **Search Query**: *(CIM-based query shown above)*
* **Security Domain**: Identity
* **Severity**: High
* **Kill Chain Phase**: Exploitation
* **MITRE ATT\&CK**: T1110 (Brute Force)
* **CIS 20**: Control 16 (Account Monitoring)
* **NIST**: AC-7, AC-2(5)

📸 Screenshot: `5_correlation_rule_form.png`

---

## 🚨 Notable Event Configuration

* **Title**:
  `Brute Force Alert: $Authentication.user$ had $failed_count$ failures from $Authentication.src$`

* **Description**:
  `User $Authentication.user$ had multiple failed login attempts (>=5) from source $Authentication.src$. A successful login may have followed at $success_time$. Investigate possible credential compromise.`

* **Drill-down Search**:

```spl
index=main (EventCode=4625 OR EventCode=4624) user=$Authentication.user$ src=$Authentication.src$
```

📸 Screenshot: `6_notable_event_top.png`

---

## 🧪 Detection Analysis

During implementation and testing, the following observations were made:

* A total of **64 correlation results** were observed using the data model–based SPL. All involved multiple failed login attempts (`failed\_count >= 5`), but **no corresponding successful login events** were identified.
* The internal host `xxx.xx.xx.50` was most frequently targeted by various external IPs, repeatedly attempting logins using admin-like usernames (`admin`, `root`, `fortinet`, `ubuntu`).
* Source IPs such as 125.133.17.163 and 112.169.8.251 attempted hundreds of login failures, signaling persistent, possibly scripted, attack behavior.
* Raw log search showed failed login attempts from users like `RAHUL`, `aravind`, and `kishore`, which were not reflected in the data model—suggesting normalization.
* Absence of any successful login despite high failure volume indicates password policies or external-facing access controls were effective at this stage.
* The correlation rule triggered a **real-time notable event**, proving the effectiveness of the detection logic.
  📸 Screenshot: `8_notable_event_triggered.png`

---

## 🖼️ Screenshots

| Stage                               | Screenshot                       |
| ----------------------------------- | -------------------------------- |
| Raw failed login SPL                | `1_failed_login_raw.png`         |
| Raw success login SPL               | `2_success_login_raw.png`        |
| Raw correlation SPL (append method) | `3_combined_raw_append.png`      |
| Data model correlation SPL          | `4_datamodel_combined.png`       |
| Correlation rule form               | `5_correlation_rule_form.png`    |
| Notable configuration form          | `6_notable_event_top.png`        |
| Rule listed in Content Mgmt         | `7_rule_content_mgmt_listed.png` |
| Notable event triggered (Incident)  | `8_notable_event_triggered.png` |

---

## 🎓 Learning Outcomes  

✅ Detected real-world brute-force attempts using Windows Event IDs (4625, 4624) from live production logs  
✅ Validated detection logic using both raw log-based SPL and CIM Authentication data model correlation  
✅ Designed efficient drill-down searches to accelerate SOC analyst triage and root-cause investigation   
✅ Mapped detection logic to MITRE ATT\&CK (T1110), Kill Chain phase, CIS Controls, and NIST standards   
✅ Strengthened end-to-end understanding of SOC workflows: detection → correlation → alert → triage → response  
✅ Triggered a live notable event in Splunk ES, confirming reliability of detection and alert configuration  

---

## ✍️ Author

**Rahul Krishna R** 
Defensive Security Enthusiast | Hands-on with SOC, Threat Detection & Splunk Enterprise Security
This project is part of my practical cybersecurity portfolio focused on real-world detection engineering.

```
