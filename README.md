# MITRE ATT&CK Mapper 🛡️

MITRE ATT&CK Mapper is a tool designed to fetch and analyze CVE (Common Vulnerabilities and Exposures) details, map them to MITRE ATT&CK techniques, identify possible threat actors, and suggest mitigations. The tool leverages multiple APIs, including the [NVD API](https://nvd.nist.gov/), [MITRE ATT&CK](https://attack.mitre.org/), and [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

---

## 🔥 Features
- 📌 Fetches CVE details from the NVD API
- 🔍 Maps CVEs to MITRE ATT&CK techniques
- 🕵️ Identifies potential threat actors
- ✅ Provides recommended mitigations
- 🖥️ Displays results in a clean and structured format

---

## 📷 Screenshot
![MITRE ATT&CK Mapper](image.png)

---

## 🚀 Installation

### Prerequisites
Ensure you have Python 3 installed. You can check your version with:
```sh
python --version
```
<br />
Clone the Repository:
```sh
git clone https://github.com/YourGitHubUsername/Mitre-Attack-Mapper.git
cd Mitre-Attack-Mapper
```

<br />
Install Dependencies:
```sh
pip install -r requirements.txt
```

<br />
Run the script and enter the CVE ID to analyze:
```sh
python mitre_mapper.py
```
