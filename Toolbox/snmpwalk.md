> SNMP scanner that can be used to gather a wealth of information from devices with guessable SNMP community strings


#SNMP_Enumeration #SNMP

## Example Windows SNMP MIB Values

| MIB Value                | Description               |
|--------------------------|---------------------------|
| `1.3.6.1.2.1.1.1`       | System description          |
| `1.3.6.1.2.1.25.1.6.0`   | System Processes          |
| `1.3.6.1.2.1.25.4.2.1.2` | Running Programs          |
| `1.3.6.1.2.1.25.4.2.1.4` | Processes Path            |
| `1.3.6.1.2.1.25.2.3.1.4` | Storage Units             |
| `1.3.6.1.2.1.25.6.3.1.2` | Software Name             |
| `1.3.6.1.4.1.77.1.2.25`  | User Accounts             |
| `1.3.6.1.2.1.6.13.1.3`   | TCP Local Ports           |
| `1.3.6.1.2.1.2.2.1.2`    | Interface Description     |
| `1.3.6.1.2.1.2.2.1.5`    | Interface Speed           |
| `1.3.6.1.2.1.2.2.1.8`    | Interface Oper Status      |
| `1.3.6.1.2.1.2.2.1.10`   | Interface In Octets       |
| `1.3.6.1.2.1.2.2.1.16`   | Interface Out Octets      |
| `1.3.6.1.2.1.2.2.1.20`   | Interface In Discards     |
| `1.3.6.1.2.1.2.2.1.14`   | Interface In Errors       |
| `1.3.6.1.2.1.2.2.1.18`   | Interface Out Errors      |
| `1.3.6.1.2.1.6.13.1.12`  | TCP Local Address         |
| `1.3.6.1.2.1.6.13.1.13`  | TCP Local Port            |
| `1.3.6.1.2.1.6.13.1.14`  | TCP Remote Address        |
| `1.3.6.1.2.1.6.13.1.15`  | TCP Remote Port           |
| `1.3.6.1.2.1.7.1.0`      | UDP In Datagrams          |
| `1.3.6.1.2.1.7.4.0`      | UDP Out Datagrams         |
| `1.3.6.1.2.1.4.22.1.2`   | IP Route Next Hop         |
| `1.3.6.1.2.1.4.22.1.3`   | IP Route Mask             |
| `1.3.6.1.2.1.4.22.1.4`   | IP Route Metric           |

## snmpwalk
> SNMP scanner that can be used to gather a wealth of information from devices with guessable SNMP community strings

View SNMP agent extensions that can execute external commands
```bash
sudo apt-get install snmp-mibs-downloader 
snmpwalk -v2c -c public 192.168.123.169 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

Using `snmpwalk` to enumerate the entire MIB tree
```bash
snmpwalk -c public -v1 -t 10 192.168.69.123
```
```bash
snmpwalk -c public -v2c -t 10 192.168.69.123
```

Using `snmpwalk` to enumerate Windows users with a valid community string
```bash
snmpwalk -c public -v1 192.168.69.123 1.3.6.1.4.1.77.1.2.25
```

Using `snmpwalk` to enumerate Windows processes with a valid community string
```bash
snmpwalk -c public -v1 192.168.69.123 1.3.6.1.2.1.25.4.2.1.2
```

Using `snmpwalk` to enumerate installed software with a valid community string
```bash
snmpwalk -c public -v1 192.168.69.123 1.3.6.1.2.1.25.6.3.1.2
```

Using `snmpwalk` to enumerate open TCP ports with a valid community string
```bash
snmpwalk -c public -v1 192.168.69.123 1.3.6.1.2.1.6.13.1.3
```
