import time
from datetime import datetime
import sqlite3

def CleanDB():
    time.sleep(60*5)
    db = sqlite3.connect('netdefdb.sqlite3')
    cursor = db.cursor()
    while 1:
        x=str(datetime.now())
        time.sleep(60*10)
        cursor.execute('DELETE FROM TCP WHERE pack_time<=?',(x,))
        db.commit()
        print("DB cleaned from "+x)
        

