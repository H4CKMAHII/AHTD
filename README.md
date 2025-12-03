



---

#  Advanced HoneyTrap Detector (AHTD)

**AHTD** is an advanced honeypot & deception-layer detection toolkit that performs low-level network probing and high-level HTTP behavior analysis to detect honeypots, filtered servers, WAF layers, decoys, and virtualized environments.

---

#  Installation

### **1. Clone the Repository**

```bash
git clone https://github.com/H4CKMAHII/AHTD.git
cd AHTD
```

### **2. Install Python Dependencies**

Make sure you're using **Python 3.8+**.

Install required libraries:

```bash
pip install -r requirements.txt
```





### **3. Run with Root/Administrator Privileges**

Many probes (A.1, A.2, A.4, A.5) require raw packet sending.

Linux / macOS:

```bash
sudo python3 honeypot.py <target_url>
```

Windows (PowerShell as Administrator):

```bash
python honeypot.py <target_url>
```

---

#  Features

### 🔍 Low-Level Network Probes

(Requires **Scapy + root**)

* TTL fingerprinting
* Xmas (FPU) flag response
* FIN scan
* NULL scan
* TCP Window Size
* TCP Options fingerprint
* Unassigned port behavior

###  HTTP Behavioral Probes

* Response timing analysis (200 vs 404)
* X-Forwarded-For reflection test
* Honeypot banner fingerprinting (Cowrie, Dionaea, Kippo, Honeyd)

###  Environment Probing

* VM detection via MAC OUI (VirtualBox, VMware, Hyper-V, KVM)

---

#  Usage

### Basic Example

```bash
sudo python3 honeypot.py https://example.com
```

### Example Terminal Output

```
[INFO] Resolved example.com to 93.184.216.34
--- Starting Advanced HoneyTrap Detector ---
...
FINAL HONEYTRAP DETECTION REPORT
Total Deception Score: 13
Conclusion: HIGH SUSPICION. NORMAL SERVER Deception Layer indicated.
```

---

#  Scoring System

| Score    | Meaning                       |
| -------- | ----------------------------- |
| **0–3**  | 🟢 Low Suspicion              |
| **4–8**  | 🟡 Moderate Suspicion         |
| **9–15** | 🟠 High Suspicion             |
| **15+**  | 🔴 Critical — Likely Honeypot |

---

#  Project Structure

```
/honeypot.py
/README.md
/requirements.txt
```

---



#  Legal Disclaimer

This project is for **educational, research, and authorized pentesting only**.
Unauthorized scanning may be illegal.

---

#  Author

Developed by **H4CKMAHII**

---


 Author

Developed by **H4CKMAHII**
Advanced Cybersecurity Research Project

---
