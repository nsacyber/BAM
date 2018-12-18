
import sqlite3

DBCONN = sqlite3.connect("..\\WSUS_Update_Data.db",
                         check_same_thread=False, isolation_level=None)

# table names
UPDATEFILESDBNAME = "UpdateFiles"
SYMBOLFILESDBNAME = "SymbolFiles"
PATCHEDFILESDBNAME = "PatchedFiles"

def updatetablewocolumn(tabletoupdate, colmlist):
    
    dbcursor = DBCONN.cursor()
    result = None

    try:
        dbcursor.execute("BEGIN TRANSACTION;")
        
        dbcursor.execute("CREATE TABLE temp_" + str(tabletoupdate) + " AS SELECT " + colmlist +
            " FROM " + str(tabletoupdate))
        dbcursor.execute("DROP TABLE " + str(tabletoupdate))
        dbcursor.execute("ALTER TABLE temp_" + str(tabletoupdate) + " RENAME TO " + str(tabletoupdate) + ";") 
        dbcursor.execute("END TRANSACTION")
        DBCONN.commit()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result

def updatetableaddcol(tabletoupdate, cdef):
    global DBCONN
    dbcursor = DBCONN.cursor()
    
    result = None

    try:
        dbcursor.execute("BEGIN TRANSACTION;")
        dbcursor.execute("ALTER TABLE " + str(tabletoupdate) + " ADD COLUMN " + 
            str(cdef) + ";")
        dbcursor.execute("END TRANSACTION;")

        DBCONN.commit()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result

def updatetablerenamecol(db_conn, tabletoupdate, cnamefrom, cnameto):
    global DBCONN
    dbcursor = DBCONN.cursor()

    result = None

    try:
        dbcursor.execute("BEGIN TRANSACTION;")
        dbcursor.execute("ALTER TABLE " + str(tabletoupdate) + " RENAME COLUMN " + str(cnamefrom) +
            " TO " + str(cnameto) + ";")

        DBCONN.commit()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result

def verifytables(tablename):
    dbcursor = DBCONN.cursor()

    result = None

    try:
        dbcursor.execute("PRAGMA table_info(" + tablename + ");")
        result = dbcursor.fetchall()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result

def verifytabledata(tablename):
    dbcursor = DBCONN.cursor()
    
    result = None

    try:
        dbcursor.execute("SELECT * FROM " + tablename + ";")
        result = dbcursor.fetchall()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result

def countcolumnentries(tablename, colname):
    dbcursor = DBCONN.cursor()
    
    result = None

    try:
        dbcursor.execute("SELECT COUNT(" + colname + ") FROM " + tablename + ";")
        result = dbcursor.fetchall()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        result = None
    
    dbcursor.close()
    return result


if __name__ == "__main__":
    print("Manual DB table update")

    '''
    Example (Adding adding a new column and removing an old column), no error handling
        print(verifytables(UPDATEFILESDBNAME)) # show old schema for table
        updatetableaddcol(UPDATEFILESDBNAME, "foobar text") # columnname column_type, add new column to existing table
        print(verifytables(UPDATEFILESDBNAME)) # show old schema for old table with new column added
        updatetablewocolumn(UPDATEFILESDBNAME, "column1, column2, column3") # create a new table with the columns to KEEP only and deleting old table
        print(verifytables(UPDATEFILESDBNAME)) # show new schema for table
    '''

    DBCONN.close()