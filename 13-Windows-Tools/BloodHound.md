## Overview

BloodHound is a tool for analyzing Active Directory security and finding attack paths.

### Components

- BloodHound: Neo4j-based analysis engine
- SharpHound: Data collector for Windows
- BloodHound.py: Python-based collector

### Data Collection

#### SharpHound (Windows)

```
.\SharpHound.exe -c All -d domain.local
```

```
.\SharpHound.exe --CollectionMethod All --Domain domain.local
```

#### BloodHound.py (Linux)

```
bashbloodhound-python -u username -p password -ns dc-ip -d domain.local -c all
```

### Analysis Queries

Find Domain Admins

```
cypherMATCH (u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN u.name
```

Find Shortest Path to Domain Admin

```
cypherMATCH (u:User {name:"USERNAME@DOMAIN.LOCAL"}), (g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}), p=shortestPath((u)-[*1..]->(g)) RETURN p
```

Find Kerberoastable Users

```
cypherMATCH (u:User {hasspn:true}) RETURN u.name
```

### Installation

Neo4j

```
sudo apt install neo4j
```

BloodHound

```
sudo apt install bloodhound
```

Python collector

```
pip install bloodhound
```