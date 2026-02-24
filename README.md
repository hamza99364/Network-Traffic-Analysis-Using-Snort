# Network Traffic Analysis Using Snort

## 📌 Project Overview
This project demonstrates network traffic monitoring and intrusion detection using industry-standard cybersecurity tools.

The objective was to simulate a reconnaissance attack and analyze the generated traffic using packet capture and IDS techniques.

---

## 🛠 Tools Used
- Kali Linux
- Metasploitable 2
- Nmap
- tcpdump
- Wireshark
- Snort 3 IDS

---

## 🌐 Network Setup
- Attacker Machine (Kali Linux): 192.168.**.***
- Target Machine (Metasploitable 2): 192.168.**.***
- Interface Used: eth0
- Environment: VirtualBox Internal Network

---

## 🚀 Step 1: Port Scanning using Nmap

Command:
nmap -sS 192.168.**.**
Copy code

Performed SYN scan to identify open ports on the target machine.

---

## 📡 Step 2: Packet Capture using tcpdump

Capture command:
sudo tcpdump -i eth0


Filtered SYN packets:
sudo tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'


Observed TCP SYN packets being sent to multiple ports.

---

## 🔎 Step 3: Packet Analysis using Wireshark

Filter used:
tcp.flags.syn == 1 && tcp.flags.ack == 0


Analyzed TCP handshake behavior and reconnaissance pattern.

---

## 🚨 Step 4: Intrusion Detection using Snort

Snort run command:
sudo snort -c /etc/snort/snort.lua -i eth0 -A alert_fast


Custom rule added:
alert tcp any any -> 192.168.**.** any (flags:S; msg:"SYN Scan Detected"; sid:1000001; rev:1;)


Result:
Snort successfully detected the SYN port scan attack and generated alerts.

---

## 🎯 Skills Demonstrated
- Packet sniffing
- TCP/IP analysis
- Reconnaissance detection
- IDS configuration
- Custom rule creation
- Network traffic monitoring

---

## 📚 Conclusion
This project demonstrates practical implementation of network traffic analysis and intrusion detection using real-world tools.

The simulated attack was:
- Captured using tcpdump
- Analyzed using Wireshark
- Detected using Snort IDS

This reflects real SOC monitoring workflow.
