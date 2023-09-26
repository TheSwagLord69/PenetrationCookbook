> GUI-based integrated platform for web application security testing. It provides several different tools via the same user interface


# Usage

#Web_Application 

Starting Burp Suite from a terminal shell
```bash
burpsuite
```

Configure Firefox browser to use Burp Suite as a proxy
- Download a copy of your Burp CA certificate
	- Access the Burp Proxy in-browser interface by visiting `http://burpsuite`
- Import cert to `about:preferences#privacy`
	- Trust the cert
- In Firefox, navigate to `about:preferences#general`, scrolling down to _Network Settings_, then clicking _Settings_.
- Choose the _Manual_ option, setting the appropriate IP address and listening port. 
- In our case, the proxy (Burp) and the browser reside on the same host, so we'll use the loopback IP address 127.0.0.1 and specify port 8080.
	- HTTP Proxy 127.0.0.1 8080
	- HTTPS Proxy 127.0.0.1 8080
	- SOCKS v4 Host 127.0.0.1 9060
- Enable this proxy server for all protocol options to ensure that we can intercept every request while testing the target application.