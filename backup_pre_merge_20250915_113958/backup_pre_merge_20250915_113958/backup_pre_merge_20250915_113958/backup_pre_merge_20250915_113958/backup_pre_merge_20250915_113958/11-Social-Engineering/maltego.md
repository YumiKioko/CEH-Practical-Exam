
---
# 🕵️ Maltego: Open Source Intelligence & Link Analysis Tool

## 📌 Overview

**Maltego** is a data mining and link analysis tool developed by **Paterva**. It is widely used in **open-source intelligence (OSINT)**, **cyber investigations**, and **social engineering** to discover relationships between people, domains, IPs, organizations, social media profiles, and more.

> 🧠 **Purpose:** Uncover hidden connections using real-time, visual link mapping of entities from various public data sources.

---
## 🎯 Key Features

- 🌐 **Graphical Link Analysis** of entities (people, domains, IPs, emails, etc.)
- 🔎 **OSINT Automation** using Transforms
- 🧬 **Relationship Mapping** across data sources
- 🔄 **Integration with APIs & Third-Party Data Providers**
- 🧩 **Transform Hub** for custom or premium data sources

---
## 🛠️ Editions

| Edition                            | Description                             | Use Case                      |
| ---------------------------------- | --------------------------------------- | ----------------------------- |
| **Maltego CE (Community Edition)** | Free version with limited functionality | Personal or academic research |
| **Maltego Pro**                    | Full feature set with commercial use    | Professional investigations   |
| **Enterprise Server**              | For large teams and SOCs                | Collaboration & data sharing  |

---
## 🚀 Installation

### 🖥️ System Requirements

- Java 11 or higher    
- Windows, macOS, or Linux

### 📦 Installation Steps

1. Download from: [https://www.maltego.com/downloads/](https://www.maltego.com/downloads/)
2. Register and activate the license (CE or commercial)
3. Launch Maltego and log in
4. Install desired Transforms via the **Transform Hub**

---
## 🧭 Core Concepts

### 🔹 Entities

- Basic data points like **Person**, **Email Address**, **Website**, **Phone Number**, etc.

### 🔹 Transforms

- Small queries that extract related data for an entity.
- Example: Transform on an email might fetch related breaches or social media accounts.

### 🔹 Graph View

- Visual canvas that maps all relationships and links between entities.
- Nodes = Entities, Lines = Relationships

---
## 🔍 Example Use Cases

| Use Case                 | Example                                   |
| ------------------------ | ----------------------------------------- |
| 🕵️ Person Investigation | Find social media, leaked data, aliases   |
| 🌐 Domain OSINT          | Map IPs, WHOIS info, subdomains           |
| 📧 Email Enumeration     | Check breaches, social profiles, PGP keys |
| 🏢 Company Recon         | Employees, websites, metadata, tech stack |
| 💳 Fraud Detection       | Connect wallet addresses, email scams     |

---
## 🧩 Transform Sources

- **Built-in**: WHOIS, DNS, Shodan, Social Networks
- **Third-Party** (via Transform Hub):

    - **HaveIBeenPwned**        
    - **VirusTotal**
    - **BuiltWith**
    - **SocialLinks**
    - **Censys**
    - **CipherTrace** (Crypto investigations)

---
## 🛡️ Red Team / Social Engineering Usage

- Pretext development (find targets, relationships)
- Mapping internal employee structures
- Discovering open ports, leaked info before phishing
- Correlating public identities across platforms

> ⚠️ Always use in compliance with laws and obtain proper authorization.

---
## 🎓 Learning Resources

- 📚 [Maltego Documentation](https://docs.maltego.com/)
- 📺 [YouTube Tutorials](https://www.youtube.com/c/MaltegoOfficial)
- 💬 [Maltego Community Forums](https://community.maltego.com/)

---
## 🧠 Pro Tips

- Combine  **Shodan**.

To combine **Maltego** with **Shodan**, you need to use **Shodan Transforms** within Maltego. These allow you to query Shodan data (like open ports, banners, vulnerabilities, etc.) and visually map it in Maltego graphs.

Here’s a **step-by-step guide** in Markdown format for combining **Maltego with Shodan**:

---

# 🔄 Integrating Shodan with Maltego

## 📌 Overview

**Shodan** is a search engine for Internet-connected devices. When integrated into **Maltego**, you can visually analyze:

- Open ports
- Service banners
- Vulnerabilities (CVEs)
- Geolocation and metadata
- Host fingerprints

---
## 🛠️ Requirements

- ✅ A **Shodan account** (free or paid)
- ✅ A **Shodan API key**
- ✅ Maltego (Community or Commercial)
- ✅ Internet access

---
## 🔗 Step-by-Step Integration

### 1. 🔐 Get Your Shodan API Key

1. Go to: [https://account.shodan.io/](https://account.shodan.io/)
2. Sign in or create an account.
3. Navigate to **My Account** → Copy the **API Key**.

---
### 2. 🧩 Add Shodan Transforms in Maltego

1. Open **Maltego**
2. Go to the **Transform Hub**
3. Search for **"Shodan"**
4. Click **Install**
5. During installation, it will prompt you for the **API Key**
6. Paste your key and **Save**

> ✅ Once installed, Shodan transforms will appear in your right-click menu on supported entities (e.g., IP address, domain).

---
### 3. 🧪 Using Shodan Transforms

#### 🔹 Example Workflow

1. **Drag an IP Address** entity onto the canvas  
    → e.g., `8.8.8.8`
2. **Right-click** the entity → `Run Transform`
3. Choose from available **Shodan Transforms**, such as:

    - `To Shodan Host Info`
    - `To Shodan Ports`        
    - `To Shodan Vulnerabilities`
    - `To Shodan Banners

4. Analyze the relationships and details returned in the graph:

    - Open ports        
    - Services & banners
    - Vulnerable protocols (e.g., Telnet, FTP)
    - Geo info

---
## 💡 Tips & Use Cases

| Use Case            | Example                                              |
| ------------------- | ---------------------------------------------------- |
| ⚙️ Port Scanning    | Map exposed services on public IPs                   |
| 🧠 Recon            | Identify insecure devices before red team engagement |
| 🛡️ Threat Hunting  | Visualize attack surface for external assets         |
| 🧬 Pretext Crafting | Understand IoT/SCADA infrastructure via banners      |

---
## ⚠️ Notes

- Free Shodan accounts have **API limits** (e.g., 100 requests/month).
- Shodan data may be **cached**, not always real-time.
- Respect **robots.txt** and data privacy when using data in reports.

---
## ✅ Summary

| Task               | Tool                                                |
| ------------------ | --------------------------------------------------- |
| Device Discovery   | Shodan                                              |
| Visual Correlation | Maltego                                             |
| Integration        | Via Transform Hub + API Key                         |
| Result             | Powerful, real-world OSINT for red teams & analysts |

---

# 🔗 Integrating Maltego with Recon-ng

## 📌 Overview

**Recon-ng** is a modular, command-line reconnaissance framework written in Python. While **Maltego** focuses on **visualizing** relationships, Recon-ng excels at **automated data harvesting**.

> 🎯 **Goal:** Use Recon-ng to gather OSINT, then import that data into Maltego for analysis and visualization.

---

## 🧰 What You’ll Need

- 🖥️ Maltego (Community or Pro)
- 🧠 Recon-ng (latest version)
- 🐍 Python 3
- 🔐 API keys for modules (optional: Shodan, HaveIBeenPwned, etc.)

---
## ⚙️ Step 1: Install Recon-ng

```
git clone https://github.com/lanmaster53/recon-ng.git
````

```
cd recon-ng
```

```
pip3 install -r REQUIREMENTS
```

```
python3 recon-ng
```

---
## 🧪 Step 2: Use Recon-ng to Gather Data

### Example: Find Emails for a Domain

```
workspaces select acme
modules load recon/domains-contacts/whois_pocs
options set SOURCE acme.com
run

modules load recon/contacts/emailrep
run
```

Other useful modules:

- `recon/hosts-hosts/resolve`
- `recon/domains-hosts/brute_hosts`
- `recon/hosts-hosts/shodan_hostname`

---
## 📁 Step 3: Export Recon-ng Data

Once you’ve gathered data (emails, hosts, etc.), export it using the `export` command:

```bash
export csv /tmp/acme_recon.csv
```

This CSV will contain the discovered entities.

---
## 📥 Step 4: Import into Maltego

### Option A: Use Maltego CSV Import Wizard

1. Open Maltego → **Import** → **Import Entities from a Table (CSV)**    
2. Select your exported CSV file
3. Map columns to entity types (e.g., emails, domains, IPs)
4. Finish import to add them to your graph
### Option B: Use **Custom Python Script**

If you want to automate the process:

```python
# recon_to_maltego.py
import csv

with open('acme_recon.csv', 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        print(f"<Entity Type='maltego.EmailAddress'><Value>{row['email']}</Value></Entity>")
```

Output this to an XML or Maltego-compatible format if you want to integrate via API or CaseFile.

---
## 💡 Bonus: Bidirectional Workflow

| Task                      | Tool             |
| ------------------------- | ---------------- |
| Rapid OSINT               | 🔍 Recon-ng      |
| Link Visualization        | 🕸️ Maltego      |
| Data Enrichment           | 🧪 Both          |
| Automated Export → Import | 🛠️ CSV, scripts |

---
## ✅ Use Cases

| Scenario              | Workflow                                |
| --------------------- | --------------------------------------- |
| Target Domain Recon   | Recon-ng → Export → Maltego             |
| Email Breach Analysis | Recon-ng (HaveIBeenPwned) → Maltego     |
| Visual Reporting      | Recon-ng → Maltego graphs               |
| Phishing Pretexting   | Maltego graphing → Enrich with Recon-ng |

---
## 🧠 Pro Tip

You can automate this workflow with a bash script or Python to:

- Run Recon-ng modules    
- Export data
- Transform for Maltego
- Automatically import into graphs
