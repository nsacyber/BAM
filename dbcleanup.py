import sqlite3

try:
    DBCONN = sqlite3.connect("WSUS_Update_Data.db",
                            check_same_thread=False, isolation_level=None)

    DBCONN.execute("pragma journal_mode=wal")
    DBCONN.execute("pragma synchronous=NORMAL")

    DBCONN.commit()
    
    DBCONN.close()
except sqlite3.Error as error:
    print("Error caught: ", error.args[0])
except:
    print("Error caught")

