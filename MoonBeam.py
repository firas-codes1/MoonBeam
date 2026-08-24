from scapy.all import *
import sqlite3
from NetDefIPGrab import ObtainIP
from NetDefAnalyzer import Analyzer
from NetDefDBClean import CleanDB
import threading


#Get IP address of gateway
IpList=ObtainIP()
if IpList==0:
    pass #exit

InnIP=IpList[0]
ExtIP=IpList[1]

#prepare port list
regscan=[]
with open("regscan.txt", "r", encoding="utf-8") as f:
    for line in f:
        regscan.append(int(line.strip()))
print("Prepared port list")

#Prepare database
db = sqlite3.connect('netdefdb.sqlite3')

#Create tables
cursor = db.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS TCP(id INTEGER PRIMARY KEY,src_ip TEXT,dst_ip TEXT, port INTEGER, flags TEXT, pack_time TIMESTAMP) ')
db.commit()
print("Database ready")


print("Started")
thread=threading.Thread(target=CleanDB)
thread.start()
sniff(filter="ip and tcp", store=False,
      prn=lambda pack:Analyzer(pack,cursor,db,IpList,regscan))

