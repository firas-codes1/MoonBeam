#MoonBeam
MoonBeam is a lightweight intrusion detection tool designed to detect Nmap port scanning patterns. In particular: SYN, XMAS (-sX), Null (-sN), FIN(-sF), and ACK(-sA). 

Detection method:
Utilizing an SQLite database, MoonBeam sniffs network packets, records metadata, and monitors incoming TCP packets based on destination IP, and then examines the flags for malicious patterns. 
For example, if a FIN is sent from IP1 to IP2, and there was no previous exchange between them, MoonBeam issues a warning. 

Mapping to MITRE ATT&CK:
Detected activity by MoonBeam maps to different ATT&CK tactics depending on where it is deployed.
If it's deployed on external network (public-facing): activity maps to Reconnaissance (TA0043) – T1595 Active Scanning.
Else, if it's deployed on internal network then activity maps to Discovery (TA0007) – T1046 Network Service Discovery. 

Room for improvement and customization:
-Use of whitelists instead of blacklists for both IPs and ports.
-More advanced behavioral analysis.
-Enhanced alerting and logging.
-Integration with SIEM tools. 
-Detecting UDP and ICMP packets.

Limitations:
-Detection is based on TCP flag behavior and may generate false positives in environments with high network traffic.
-Does not perform payload inspection or application-layer analysis
-Limited to TCP-based detection; does not currently detect UDP or ICMP scanning techniques.
