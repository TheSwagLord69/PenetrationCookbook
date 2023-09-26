> Simple SNMP scanner which sends SNMP requests for the sysDescr value asynchronously with user-adjustable sending times and then logs the responses which gives the description of the software running on the device.


#SNMP_Enumeration

Brute force community strings
```bash
echo public > community
echo private >> community
echo manager >> community
for ip in $(seq 1 254); do echo 192.168.69.$ip; done > ips
onesixtyone -c community -i ips
```
