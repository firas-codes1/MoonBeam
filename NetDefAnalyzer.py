from scapy.all import *
import sqlite3
import datetime
from NetDefIPGrab import ObtainIP

insert_query='INSERT INTO TCP(src_ip, dst_ip, port, flags, pack_time)VALUES(?,?,?,?,?)'
select_query='SELECT flags FROM TCP WHERE src_ip=? AND port=? ORDER BY id DESC LIMIT 1'
SYNselect_query='SELECT flags FROM TCP WHERE src_ip=? AND NOT port=? ORDER BY id DESC LIMIT 10'

def Analyzer(pack,cursor,db,ips,regscan):
    #check if destination IP is in the list.
    if (pack[IP].dst==ips[0]) or (pack[IP].dst==ips[1]):
        

        if TCP in pack:
            
            #Record packet metadata in database
            PacketTime=datetime.datetime.fromtimestamp(pack[TCP].time).strftime('%Y-%m-%d %H:%M:%S.%f') #convert timestamp to string
            PacketTime=datetime.datetime.strptime(PacketTime, '%Y-%m-%d %H:%M:%S.%f') #convert time str to date object that can be inserted into sqlite3 TIMESTAMP type column
            cursor.execute(insert_query,
                        (pack[IP].src,pack[IP].dst,int(pack[TCP].dport), str(pack[TCP].flags), PacketTime ),)
            db.commit() 


            if pack[TCP].flags=="S":
                if pack[TCP].dport in regscan:
                    cursor.execute(SYNselect_query,(pack[IP].src,pack[TCP].dport)) #Get pattern for SYN packets 
                    try:
                        result=cursor.fetchall()[0]
                    except:
                        result=("","")

                    x=0
                    for flag in result:
                        #Check how many times this IP sent SYN to other ports
                        if flag=="S":
                            x+=1
                        else:
                            pass
                    if x>=1:
                        print("ALERT! "+pack[IP].src+" sent SYN to port "+str(pack[TCP].dport)+" / Possible SYN scan pattern detected")

            #NULL Packets
            if pack[TCP].flags=="":
                if pack[TCP].dport in regscan:
                    print("WARNING! "+pack[IP].src+" Tried to Null scan TCP port "+str(pack[TCP].dport))

            #FIN Packets
            if pack[TCP].flags=="F":
                if pack[TCP].dport in regscan:

                   cursor.execute(select_query,(pack[IP].src,pack[TCP].dport))
                   try:
                       result=cursor.fetchall()[0]
                   except:
                       result=[""] #no packets recorded.

                   if result[0]=="A":
                       #if last packet exchanged between those 2 IP addresses was a TCP ACK
                       pass
                   else:
                       print("ALERT! "+pack[IP].src+"sent unexpected FIN packet to port "+str(pack[TCP].dport))

            #XMAS scan
            if pack[TCP].flags=="FPU":
                if pack[TCP].dport in regscan:
                    print("WARNING! "+pack[IP].src+" Tried to Xmas scan TCP port "+str(pack[TCP].dport))

            #ACK packet
            if pack[TCP].flags=="A":
                if pack[TCP].dport in regscan:
                    cursor.execute(select_query,(pack[IP].src,pack[TCP].dport))
                    try:
                        result=cursor.fetchall()[0]
                    except:
                        result=[""]

                    if (result[0]=="A") or (result[0]=="SA"):
                        #pass if the last exchange between the 2 IPs was an ACK or SYNACK
                        pass
                    else:
                        print("ALERT! "+pack[IP].src+" sent unexpected ACK packet to port "+str(pack[TCP].dport))

                    