from scapy.all import *


def showpc_(pack):
    if pack[IP].dst=="216.58.198.174":
        print(pack)
        if pack[TCP].flags=="S":
            with open("regscan.txt", "a", encoding="utf-8") as f:
                f.write(str(pack[TCP].dport)+"\n")

        #flag must be S, also print port number 

def udppck(pack):
    if pack[IP].dst=="216.58.198.174":
        with open("udpregscan.txt", "a", encoding="utf-8") as f:
            f.write(str(pack[UDP].dport)+"\n")

sniff(filter="ip and udp", prn=lambda pack:udppck(pack))

#algorithm: if  apacket recieved that is S and trying to connect to any of these ports, alert. 
#If same IP sends SYN many times or to other ports, reject all from IP
