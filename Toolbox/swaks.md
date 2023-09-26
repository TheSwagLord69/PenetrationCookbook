> swaks (Swiss Army Knife SMTP) is a command-line tool written in Perl for testing SMTP setups; it supports STARTTLS and SMTP AUTH (PLAIN, LOGIN, CRAM-MD5, SPA, and DIGEST-MD5). swaks allows one to stop the SMTP dialog at any stage, e.g to check RCPT TO: without actually sending a mail.


#Email #Client_Side 

Send email using `swaks`
Username: `test@superhentaicorp.com`
Password: `test`
```bash
sudo swaks -t sales.wizard@superhentaicorp.com --from test@superhentaicorp.com -ap --attach config.Library-ms --server 192.168.185.180 --body body.txt --header "Subject: Urgent stuff" --suppress-data
```