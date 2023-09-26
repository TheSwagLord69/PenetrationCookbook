
> An open source graph database (NoSQL) that creates nodes, edges, and properties instead of simple rows and columns. This facilitates the visual representation of our collected data with BloodHound.


#Active_Directory_Enumeration 

# Download

Install Bloodhound from the apt repository
```bash
sudo apt update && sudo apt install -y bloodhound
```

# Usage

Start the Neo4j service
```bash
sudo neo4j start
```

Navigate to web application
```
http://localhost:7474
```
- Authenticate using the default credentials (_neo4j_ as both username and password)

Start BloodHound
```
bloodhound
```
- Green check mark in the first column indicates BloodHound has automatically detected that we have the Neo4j database running. 
- Log in using the _neo4j_ username and the password (P@ssw0rd) created.

Import data collected (.zip file) from SharpHound to BloodHound
```
Click "Upload Data" in top right hand corner
```

Show BloodHound Database Information
```
Click the 3 stripes icon (More Info) tab at the top-left
Click Database Info (if not pre selected)
```

Show BloodHound Analysis Overview
```
Click the 3 stripes icon (More Info) tab at the top-left
Click Analysis
```

Show all Domain Admins
```
Click the 3 stripes icon (More Info) tab at the top-left
Click Analysis
Click "Find all Domain Admins" under "Domain Information"
```

Show Shortest Paths to Domain Admins
```
Click the 3 stripes icon (More Info) tab at the top-left
Click Analysis
Click "Find Shortest Paths to Domain Admins" under "Shortest Paths"
Select Domain Admin group
```

Show additional information between connected nodes
```
Right-click the line between the nodes
Click "? Help"
```

Mark user as owned
```
Run a search (top left) on user E.g., bestsalesman@HENTAIDOMAIN.COM
Right click the object that shows in the middle of the screen
Click "Mark User as Owned"
```
- Re-run analysis after marking user(s) as owned.
	- It's a good idea to mark every object we have access to as _owned_ to improve our visibility into more potential attack vectors. 
		- There may be a short path to our goals that hinges on ownership of a particular object.

# Custom query

Display all computers
```
MATCH (m:Computer) RETURN m
```

Display all users
```
MATCH (m:User) RETURN m
```

Display all active sessions
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```
- Syntax
	- `(NODES)-[:RELATIONSHIP]->(NODES)`
