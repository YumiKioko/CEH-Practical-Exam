# 🕵️‍♂️ CREEPY: Geolocation OSINT Tool

## 📌 Overview

**CREEPY** is an open-source geolocation intelligence tool that collects geotagged information from social networks and image hosting services to provide a visual map of a person’s locations and movements.

> 🎯 **Purpose:** Track and analyze the physical locations of targets using publicly available geotagged data.

---
## 🔑 Key Features

- 📍 Extracts geolocation metadata from social media (Twitter, Flickr, Instagram, etc.)
- 🗺️ Displays gathered location data on interactive maps (Google Maps, OpenStreetMap)
- 🛠️ Supports multiple social media platforms and image hosting sites
- 🔍 Filters data by date, location, or source
- 🚀 Export collected data in KML, CSV, or GeoJSON formats for further analysis

---
## 🚀 Installation

### On Linux

```
sudo apt-get install python3-pip
```

```
pip3 install creepy
```

Alternatively, clone from GitHub:

```
git clone https://github.com/ilektrojohn/creepy.git
```

```
cd creepy
```

```
python3 setup.py install
```

---

## 🧭 How It Works

1. **Input**: Provide social media usernames, user IDs, or email addresses.
2. **Data Collection**: CREEPY scrapes geotagged posts and images.
3. **Visualization**: Maps and timelines show the movement or common locations of the target.
4. **Export**: Save data for reports or integration with other OSINT tools.

---

## 🔍 Use Cases

| Scenario                | Description                                                      |
| ----------------------- | ---------------------------------------------------------------- |
| Stalking Investigations | Analyze a suspect’s location history (legal permission required) |
| Threat Assessment       | Identify patterns in physical presence of persons of interest    |
| Journalistic Research   | Map movement patterns for investigative reporting                |
| Security Audits         | Check if employees or executives are oversharing location info   |

---
## ⚠️ Legal and Ethical Considerations

> CREEPY uses **publicly available** data, but tracking someone’s physical location raises serious privacy concerns. Always ensure you have legal authorization and a valid ethical reason before using CREEPY.

---
## 📚 Resources

- 🔗 GitHub: [https://github.com/ilektrojohn/creepy](https://github.com/ilektrojohn/creepy)
- 📘 Documentation: Included in the GitHub repo
- 📺 Tutorials: Search “CREEPY OSINT tool” on YouTube

---

## 🧠 Pro Tips

- Combine CREEPY data with Maltego for powerful visualization of digital and physical footprints.    
- Use filters carefully to focus on relevant timeframes and avoid noise.
- Check updates regularly to keep up with social media API changes.

Sure! Here's a clear Markdown guide on how to **combine CREEPY data with Maltego** for enhanced OSINT geolocation visualization:

---

# 🔗 Combining CREEPY Data with Maltego

## 🛠️ Workflow to Combine CREEPY & Maltego

### 1. Collect Geodata with CREEPY

- Run CREEPY to scrape geotagged social media posts for your target.    
- Export the gathered data as a CSV or KML file.

### 2. Prepare Data for Maltego

- If exported as KML, convert it to CSV or a tabular format that Maltego accepts.
- Ensure the CSV includes columns like:

    - `Latitude`        
    - `Longitude`
    - `Date/Time`
    - `Source` (e.g., Twitter, Instagram)
    - `Description` or `Comment`

### 3. Import Data into Maltego

- Open Maltego and create a new graph.
- Use the **Import Entities from Table (CSV)** option.
- Map your CSV columns to Maltego entities:

    - Latitude & Longitude → `Location` entity        
    - Description → `Note` or `Comment` attached to location
    - Source → Custom property or additional entity info
- Import all geolocation points as Location entities on the graph.

### 4. Visualize and Analyze

- Use Maltego’s graph features to:

    - Connect locations with timelines (date/time data)        
    - Link locations to digital identities or social media profiles
    - Add additional OSINT entities (emails, domains, IPs) to enrich context
    - Apply filters and layouts to spot movement patterns or hotspots

---

## 💡 Tips & Tricks

- Use **Transform Sets** in Maltego to automate enriching locations with nearby infrastructure or ISP data.    
- Overlay imported geodata with network or domain entities for full target profiling.
- Regularly update your CSV exports from CREEPY to keep Maltego graphs current.
- Customize Maltego entities to store extra metadata from CREEPY for richer context.

## 🔗 Useful Links

- CREEPY GitHub: [https://github.com/ilektrojohn/creepy](https://github.com/ilektrojohn/creepy)    
- Maltego Documentation: [https://docs.maltego.com/](https://docs.maltego.com/)
- CSV Import in Maltego: [https://docs.maltego.com/support/solutions/articles/15000058948-import-csv-files-into-maltego](https://docs.maltego.com/support/solutions/articles/15000058948-import-csv-files-into-maltego)
