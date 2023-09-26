> Open-source relational database management system


#MySQL #SQL

Connecting to the remote MySQL instance
```bash
mysql -u root -p'toor' -h 192.168.123.169 -P 3306
```

Connecting to the local MySQL instance
```
mysql -u hentaiuser -p'SUP4R4ND0MP45569' -h 127.0.0.1 -P 3306
```

Dumping all the databases
```bash
mysqldump -u hentaiuser -p'SUP4R4ND0MP45569' --port=3306 --all-databases > out.sql
```
```bash
mysqldump -u hentaiuser -pSUP4R4ND0MP45569 --port=3306 --all-databases > out2.sql
```

Retrieving the version of a MySQL database
```sql
select version();
```

Inspecting the current session's user
```sql
select system_user();
```

Listing all Available Databases
```sql
show databases;
```

Inspecting user's encrypted password
```sql
SELECT user, authentication_string FROM mysql.user WHERE user = 'hentaiuser';
```

Retrieving the Windows OS Version
```sql
SELECT @@version;
```

Inspecting the Available Databases
```sql
SELECT name FROM sys.databases;
```

Inspecting the Available Tables in the Database
```sql
SELECT * FROM sussydb.information_schema.tables;
```

Exploring Users Table Records
```sql
select * from sussydb.dbo.users;
```

Show columns
```mysql
SHOW COLUMNS FROM mysql.user;
```

Show plugin column
```mysql
SELECT user, plugin, authentication_string FROM mysql.user
WHERE user = 'sussyuser';
```
