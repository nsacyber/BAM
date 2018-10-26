#! python3

'''
Test a mix queries against all three DBs or a combination of all three
'''
import sqlite3


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

DBCONN = sqlite3.connect("..\\WSUS_Update_Data.db", check_same_thread=False)
DBCONN.row_factory = sqlite3.Row

CURSOR = DBCONN.cursor()
COUNT = Count()
try:

    '''
        Cases for entry verification
    '''

    testhdr("Cases for entry verification")

    header("List debugging information for a file (nlsdata0009.dll)",
           COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles WHERE "
                   "FileName = 'nlsdata0009.dll'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two public symbols", COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles WHERE PublicSymbol = 1 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two private symbols", COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles WHERE PrivateSymbol = 1 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Find two file that did not have symbols loaded (SymNone)",
           COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles "
                   "WHERE symtype = 'SymNone' LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Find two file that has PDB symbols (PDB)",
           COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles "
                   "WHERE symtype = 'SymPDB' LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Find patched file that have the PDB GUID "
           "(32E93E3E-2B54-4E01-8D1C-C2945056DED8)", COUNT)
    GUID = "32E93E3E-2B54-4E01-8D1C-C2945056DED8".lower()
    CURSOR.execute(
        "SELECT * FROM PatchedFiles WHERE Signature = '" + GUID + "' LIMIT 1")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

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

    header("Find all patched Netwtw04.sys entries", COUNT)
    CURSOR.execute("SELECT FileName,Signature,SymbolObtained,SymbolPath," +
                   "DiskPath FROM PatchedFiles "
                   "WHERE FileName = 'Netwtw04.sys'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> ", end='')
            if type(row[column]) is str:
                print(row[column].encode("utf-8").decode("utf-8"))
            else:
                print(str(row[column]))

        print("")

    header("List Netwtw04.sys Patch information", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE FileName = 'Netwtw04.sys'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> ", end='')
            if type(row[column]) is str:
                print(row[column].encode("utf-8").decode("utf-8"))
            else:
                print(str(row[column]))

        print("")

    header("List Netwtw04.sys Symbol information", COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles "
                   "WHERE FileName = 'Netwtw04.sys'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> ", end='')
            if type(row[column]) is str:
                print(row[column].encode("utf-8").decode("utf-8"))
            else:
                print(str(row[column]))

        print("")

    header("List file that contains UNKNOWN symbol loaded", COUNT)
    CURSOR.execute("SELECT FileName,SHA256,SymContains FROM SymbolFiles "
                   "WHERE SymContains = 'UNKNOWN' LIMIT 1")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List all files ignored by symchk.exe (showed in SymbolFiles)", COUNT)
    CURSOR.execute("SELECT FileName FROM SymbolFiles "
                   "WHERE Ignored = 1 LIMIT 5")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List all files ignored by symchk.exe (showed in PatchedFiles)", COUNT)
    CURSOR.execute("SELECT FileName,DiskPath,SymbolObtained FROM PatchedFiles "
                   "WHERE Ignored = 1 LIMIT 5")

    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    '''
        Cases for correlating information
    '''

    testhdr("Cases for correlating information")

    header("Find 1 patched file that has obtained symbols", COUNT)
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
                       "WHERE Signature = '" + SIGNATURE + "' LIMIT 1") # same PE can be in many updates
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
                       "WHERE Signature = '" + SIGNATURE + "' LIMIT 1") # same PE can be in many updates
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
    CURSOR.execute("SELECT CompanyName, count(CompanyName) FROM PatchedFiles "
                   "GROUP BY CompanyName")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two PE files with an Age of 0", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE Age = 0 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two PE files with an Age of 1", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE Age = 1 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two PE files with an Age greater than 3", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE Age > 3 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two PE files with no Age value found", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE Age = -1 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Find 1 PE file without debugging information", COUNT)
    CURSOR.execute("SELECT * FROM PatchedFiles "
                   "WHERE Ignored != 1 AND StrippedPE = 1 LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")


    '''
        Cases for querying PDB information
    '''

    testhdr("Cases for querying PDB information")

    header("List two symbol files with PDB20 signatures", COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles WHERE PDB20Sig != '0' and PDB20Sig != '' LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List two symbol files with PDB70 signatures equal to zero", COUNT)
    CURSOR.execute("SELECT * FROM SymbolFiles "
                   "WHERE PDB70Sig = '{00000000-0000-0000-0000-000000000000}' AND symcontains != '' LIMIT 2")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")


    '''
        Cases for dealing with Update files
    '''

    testhdr("Cases for dealing with Update files")

    header("Find 1 Update file", COUNT)
    CURSOR.execute("SELECT * FROM UpdateFiles LIMIT 1")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")


    header("Find which update win32k.sys (3f849e16-31a6-4ee0-9419-47ece045161a) "  +
           "came from", COUNT)
    print("Use disk path to find update ID")
    CURSOR.execute("SELECT FileName,DiskPath FROM PatchedFiles "
                   "WHERE Signature = '3f849e16-31a6-4ee0-9419-47ece045161a'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print("{} --> {}".format(column, row[column]))

    '''
        Cases for providing various statistical results
    '''

    testhdr("Cases for providing various statistical results")

    header("List the different type of Symbols loaded (grouped)", COUNT)
    CURSOR.execute("SELECT SymContains, count(SymContains) FROM SymbolFiles GROUP BY SymContains")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
    print("")

    header("List all Symbol Types", COUNT)
    CURSOR.execute("SELECT symtype, count(symtype) FROM SymbolFiles "
                   "GROUP BY symtype")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("List count of reasons files were ignored", COUNT)
    CURSOR.execute("SELECT IgnoredReason,count(IgnoredReason) FROM SymbolFiles "
                   "GROUP BY IgnoredReason")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total PE patched files extracted (not ignored)", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM PatchedFiles "
                   "WHERE Ignored = 0")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total symbol files obtained (not ignored)", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM SymbolFiles "
                   "WHERE Ignored = 0 AND SymContains != 'no symbols loaded'")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total PE patched files ignored", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM PatchedFiles WHERE Ignored = 1")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total symbol files ignored", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM SymbolFiles WHERE Ignored = 1")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total PE patched files extracted (i.e., entered into DB) (ignored and not ignored)", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM PatchedFiles")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total symbol files enter into DB (ignored and not ignored)", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM SymbolFiles")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")

    header("Total Updates files enter into DB", COUNT)
    CURSOR.execute("SELECT count(FileName) FROM UpdateFiles")
    for row in CURSOR.fetchall():
        for column in row.keys():
            print(column + " --> " + str(row[column]))
        print("")



    '''
    From symchk.exe's various output
    Result              0x00030001 - public symbols loaded
    Result              0x00010001 - no symbols loaded
    Result              0x00000000 - Ignored file
    Result              0x000f0001 - private symbols & lines
    '''

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
