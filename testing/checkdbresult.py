#! python3

'''
Test a mix queries against all three DBs or a combination of all three
'''
import sqlite3

import sys

import os

class Count:
    '''
     Just a count
    '''

    count = 1

    def __init__(self):
        self.count = 1

    def inccnt(self):
        '''
        inccnt
        '''
        self.count += 1

def testhdr(msg):
    print("\n\n")
    print("*"*80 + "\n")
    print(msg + "\n")
    print("*"*80 + "\n\n")

def header(msg, countc):
    '''
    header
    '''

    cnt = str(countc.count)
    print("...............TEST " + cnt + "...............")
    print(msg)
    print("........")
    countc.count += 1

def sqliteexecute(query):
    try:
        CURSOR.execute(query)
        for row in CURSOR.fetchall():
            for column in row.keys():
                print(column + " --> " + str(row[column]))
            print("")
    except sqlite3.Error as error:
        print("Error caught: ", error.args[0])

CURSOR = ""

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print("Requires arguments: [filename] [guid] [updateguid]")
        sys.exit(-1)

    DBCONN = sqlite3.connect("..\\WSUS_Update_Data.db", check_same_thread=False)
    DBCONN.row_factory = sqlite3.Row

    CURSOR = DBCONN.cursor()
    COUNT = Count()

    filetofind = guidtofind = updateguidtofind = ""

    if len(sys.argv) < 3:
        filetofind = os.path.basename(sys.argv[1])
    elif len(sys.argv) < 4:
        guidtofind = sys.argv[2]
    elif len(sys.argv) < 5:
        updateguidtofind = sys.argv[3]

    try:

        '''
            Cases for entry verification
        '''
        
        testhdr("Cases for entry verification")

        if len(sys.argv) < 3:
            header("List debugging information for a file ("+filetofind+")",
                COUNT)
            sqliteexecute("SELECT * FROM SymbolFiles WHERE FileName = '"+filetofind+"'")

        header("List two public symbols", COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE PublicSymbol = 1 LIMIT 2")

        header("List two private symbols", COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE PrivateSymbol = 1 LIMIT 2")

        header("Find two file that did not have symbols loaded (SymNone)",
            COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE symtype = 'SymNone' LIMIT 2")

        header("Find two file that have PDB symbols (PDB)",
            COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE symtype = 'SymPDB' LIMIT 2")

        if len(sys.argv) < 4:
            header("Find patched file that have the PDB GUID "
                "("+guidtofind+")", COUNT)
            GUID = guidtofind.lower()
            sqliteexecute("SELECT * FROM PatchedFiles WHERE Signature = '" + GUID + "' LIMIT 1")

        header("The first two patched files added to DB", COUNT)
        CURSOR.execute("SELECT * FROM PatchedFiles LIMIT 2")
        for row in CURSOR.fetchall():
            for column in row.keys():
                print(column + " --> ", end='')
                if type(row[column]) is str:
                    print(row[column].encode("utf-8").decode("utf-8"))
                else:
                    print(str(row[column]))

            print("")

        if len(sys.argv) < 2:
            header("Find all patched "+filetofind+" entries", COUNT)
            CURSOR.execute("SELECT FileName,Signature,SymbolObtained,SymbolPath," +
                        "DiskPath FROM PatchedFiles "
                        "WHERE FileName = '"+filetofind+"'")
            for row in CURSOR.fetchall():
                for column in row.keys():
                    print(column + " --> ", end='')
                    if type(row[column]) is str:
                        print(row[column].encode("utf-8").decode("utf-8"))
                    else:
                        print(str(row[column]))

                print("")

            header("List "+filetofind+" Patch information", COUNT)
            CURSOR.execute("SELECT * FROM PatchedFiles "
                        "WHERE FileName = '"+filetofind+"'")
            for row in CURSOR.fetchall():
                for column in row.keys():
                    print(column + " --> ", end='')
                    if type(row[column]) is str:
                        print(row[column].encode("utf-8").decode("utf-8"))
                    else:
                        print(str(row[column]))

                print("")

            header("List "+filetofind+" Symbol information", COUNT)
            CURSOR.execute("SELECT * FROM SymbolFiles "
                        "WHERE FileName = '"+filetofind+"'")
            for row in CURSOR.fetchall():
                for column in row.keys():
                    print(column + " --> ", end='')
                    if type(row[column]) is str:
                        print(row[column].encode("utf-8").decode("utf-8"))
                    else:
                        print(str(row[column]))

                print("")

        header("List file that contains UNKNOWN symbol loaded", COUNT)
        sqliteexecute("SELECT FileName,SHA1,SymContains FROM SymbolFiles WHERE SymContains = 'UNKNOWN' LIMIT 1")

        header("List all files ignored by symchk.exe (showed in SymbolFiles)", COUNT)
        sqliteexecute("SELECT FileName FROM SymbolFiles WHERE Ignored = 1 LIMIT 5")

        header("List all files ignored by symchk.exe (showed in PatchedFiles)", COUNT)
        sqliteexecute("SELECT FileName,DiskPath,SymbolObtained FROM PatchedFiles WHERE Ignored = 1 LIMIT 5")

        '''
            Cases for correlating information
        '''

        testhdr("Cases for correlating information")

        header("Find 1 patched file that have obtained symbols", COUNT)
        CURSOR.execute("SELECT FileName,Signature,SymbolObtained,SymbolPath," +
                    "DiskPath FROM PatchedFiles " +
                    "WHERE SymbolObtained = 1 LIMIT 1")
        SIGNATURE = ''
        FILENAME = ''
        FOUND = False

        for row in CURSOR.fetchall():
            for column in row.keys():
                print("{} --> {}".format(column, row[column]))
                if column == "Signature":
                    SIGNATURE = row[column]
                    FILENAME = row['FileName']
                    FOUND = True

        if FOUND:
            print("-----")
            print("Found symbol information for " +
                "{} ({}) were obtained.".format(FILENAME, SIGNATURE))
            print("........")
            CURSOR.execute("SELECT * FROM SymbolFiles " +
                        "WHERE Signature = '" + SIGNATURE + "' LIMIT 1")
            for row in CURSOR.fetchall():
                for column in row.keys():
                    print(column + " --> ", end='')
                    if type(row[column]) is str:
                        print(row[column].encode("utf-8").decode("utf-8"))
                    else:
                        print(str(row[column]))
        else:
            print("Nothing found...")

        FOUND = False

        header("Find 1 file Ignored by symchk.exe (Ignored reason ignored) PE -> Symbol", COUNT)
        CURSOR.execute("SELECT FileName,Signature FROM PatchedFiles "
                    "WHERE Ignored = 1 AND Signature != 'NOTFOUND' LIMIT 1")
        for row in CURSOR.fetchall():
            for column in row.keys():
                print("{} --> {}".format(column, row[column]))
                if column == "Signature":
                    SIGNATURE = row[column]
                    FILENAME = row['FileName']
                    FOUND = True

        if FOUND:
            print("-----")
            print("Found corresponding PE information for ignored file " +
                "{}, {}".format(FILENAME, SIGNATURE))
            print("........")
            CURSOR.execute("SELECT * FROM PatchedFiles "
                        "WHERE Signature = '" + SIGNATURE + "' LIMIT 1")
            for row in CURSOR.fetchall():
                for column in row.keys():
                    print(column + " --> ", end='')
                    if type(row[column]) is str:
                        print(row[column].encode("utf-8").decode("utf-8"))
                    else:
                        print(str(row[column]))
        else:
            print("Nothing found...")

        FOUND = False

        '''
            Cases for querying PE file information
        '''

        testhdr("Cases for querying PE file information")

        header("List all Company names from extracted PE files", COUNT)
        sqliteexecute("SELECT CompanyName, count(CompanyName) FROM PatchedFiles GROUP BY CompanyName")

        header("List two PE files with an Age of 0", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE Age = 0 LIMIT 2")

        header("List two PE files with an Age of 1", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE Age = 1 LIMIT 2")

        header("List two PE files with an Age greater than 3", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE Age > 3 LIMIT 2")

        header("List two PE files with no Age value found", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE Age = -1 LIMIT 2")

        header("Find 1 PE file without debugging information", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE Ignored != 1 AND StrippedPE = 1")

        '''
            Cases for querying PDB information
        '''

        testhdr("Cases for querying PDB information")

        header("List two symbol files with PDB20 signatures", COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE PDB20Sig != '0' and PDB20Sig != '' LIMIT 2")

        header("List two symbol files with PDB70 signatures equal to zero", COUNT)
        sqliteexecute("SELECT * FROM SymbolFiles WHERE PDB70Sig = '{00000000-0000-0000-0000-000000000000}' AND symcontains != '' LIMIT 2")

        '''
            Cases for dealing with Update files
        '''

        testhdr("Cases for dealing with Update files")

        header("Find 1 Update file", COUNT)
        sqliteexecute("SELECT * FROM UpdateFiles LIMIT 1")

        if len(sys.argv) < 5:
            header("Find which update ("+updateguidtofind+") "  +
                "came from", COUNT)
            print("Use disk path to find update ID")
            sqliteexecute("SELECT FileName,DiskPath FROM PatchedFiles WHERE Signature = '"+updateguidtofind+"'")

        '''
            Cases for providing various statistical results
        '''

        testhdr("Cases for providing various statistical results")

        header("List the different type of Symbols loaded (grouped)", COUNT)
        sqliteexecute("SELECT SymContains, count(SymContains) FROM SymbolFiles GROUP BY SymContains")

        header("List all Symbol Types", COUNT)
        sqliteexecute("SELECT symtype, count(symtype) FROM SymbolFiles GROUP BY symtype")

        header("List count of reasons files were ignored", COUNT)
        sqliteexecute("SELECT IgnoredReason,count(IgnoredReason) FROM SymbolFiles GROUP BY IgnoredReason")

        header("Total PE patched files extracted (not ignored)", COUNT)
        sqliteexecute("SELECT count(FileName) FROM PatchedFiles WHERE Ignored = 0")

        header("Total symbol files obtained (not ignored)", COUNT)
        sqliteexecute("SELECT count(FileName) FROM SymbolFiles WHERE Ignored = 0 AND SymContains != 'no symbols loaded'")

        header("Total PE patched files ignored", COUNT)
        sqliteexecute("SELECT count(FileName) FROM PatchedFiles WHERE Ignored = 1")

        header("Total symbol files ignored", COUNT)
        sqliteexecute("SELECT count(FileName) FROM SymbolFiles WHERE Ignored = 1")

        header("Total PE patched files extracted (i.e., entered into DB) (ignored and not ignored)", COUNT)
        sqliteexecute("SELECT count(FileName) FROM PatchedFiles")

        header("Total symbol files enter into DB (ignored and not ignored)", COUNT)
        sqliteexecute("SELECT count(FileName) FROM SymbolFiles")

        header("Total Updates files enter into DB", COUNT)
        sqliteexecute("SELECT count(FileName) FROM UpdateFiles")

        header("Find the update a PE file came from", COUNT)
        sqliteexecute("SELECT * FROM PatchedFiles WHERE UpdateId != '' LIMIT 7")

        print("...............CLOSING...............")
        print("clearing SymbolFiles table")
        print("........")
        #CURSOR.execute("DELETE FROM SymbolFiles")
        DBCONN.commit()

    except sqlite3.Error as error:
        print("Error caught: ", error.args[0])


    print("End of TEST")

    CURSOR.close()
    DBCONN.close()
