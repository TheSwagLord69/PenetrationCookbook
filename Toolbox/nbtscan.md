> A program for scanning IP networks for NetBIOS name information. It sends NetBIOS status query to each address in supplied range and lists received information in human readable form. For each responded host it lists IP address, NetBIOS computer name, logged-in user name and MAC address (such as Ethernet).


#SMB_Enumeration #SMB

Using `nbtscan` to collect additional NetBIOS information
```bash
sudo nbtscan -r 192.168.69.0/24
```
