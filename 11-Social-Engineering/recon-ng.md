# 🔍 Recon-ng: Open-Source Reconnaissance Framework

## 📌 Overview

**Recon-ng** is a powerful, modular, command-line reconnaissance framework written in Python. It provides a powerful environment to conduct open-source intelligence (OSINT) gathering efficiently and effectively.

> 🎯 **Purpose:** Automate information gathering and data enrichment from a variety of public sources with modular commands.

---

## 🧰 Key Features

- Modular architecture with over 60 built-in modules
- API integration with popular services (Shodan, HaveIBeenPwned, VirusTotal, Twitter, etc.)
- Workspaces to organize data per target/project
- Database-backed to store results
- Export data in multiple formats (CSV, JSON, XML)
- Automation-friendly with scripting capabilities

---
## 🚀 Installation

### Clone and install Recon-ng

```bash
git clone https://github.com/lanmaster53/recon-ng.git
cd recon-ng
pip3 install -r REQUIREMENTS
python3 recon-ng
```

---

## 🧭 Basic Usage

### Starting Recon-ng

```bash
./recon-ng
```

### Create/select a workspace

```bash
workspaces create example
```

```
workspaces select example
```

### Search and load modules

```
marketplace search shodan
marketplace install recon/hosts-hosts/shodan_hostname
modules load recon/hosts-hosts/shodan_hostname
```

### Set module options

```
options set SOURCE example.com
```

### Run the module

```
run
```

### Show gathered data

```
show hosts
show contacts
```

---

## 🔍 Common Modules

|Module|Description|
|---|---|
|`recon/domains-hosts/brute_hosts`|Find subdomains via brute force|
|`recon/domains-contacts/whois_pocs`|Gather domain WHOIS points of contact|
|`recon/hosts-hosts/shodan_hostname`|Get hosts related to a hostname via Shodan|
|`recon/contacts-credentials/hibp`|Check emails against HaveIBeenPwned database|
|`recon/contacts-web/social_media`|Find social media profiles related to an email or name|

---

## 📂 Exporting Data

Export results for use in other tools or reports:

```bash
export csv /path/to/file.csv
```

---

## 🔗 Integration with Other Tools

- **Maltego:** Export Recon-ng data as CSV and import into Maltego for visualization.
- **Custom Scripts:** Automate Recon-ng modules and parse/export results for further processing.

---
## 📚 Resources

- 🔗 [Recon-ng GitHub](https://github.com/lanmaster53/recon-ng)    
- 📘 [Recon-ng Wiki](https://github.com/lanmaster53/recon-ng/wiki)
- 🎥 [Recon-ng Tutorials on YouTube](https://www.youtube.com/results?search_query=recon-ng+tutorial)
