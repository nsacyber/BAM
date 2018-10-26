'''
this file contains global values and variables used throughout the application
'''
#***************************************
# Imports
#***************************************
import sqlite3

#***************************************
# Global Constants
#***************************************
# shared connection to db
DBCONN = sqlite3.connect("WSUS_Update_Data.db",
                         check_same_thread=False, isolation_level=None)

DBCONN.execute("pragma journal_mode=wal")
DBCONN.execute("pragma synchronous=NORMAL")
# to view column names
DBCONN.row_factory = sqlite3.Row
# table names
UPDATEFILESDBNAME = "UpdateFiles"
SYMBOLFILESDBNAME = "SymbolFiles"
PATCHEDFILESDBNAME = "PatchedFiles"
# enable or disable debug output
VERBOSITY = False
