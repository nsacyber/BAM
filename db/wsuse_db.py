'''
This module contains the various database management functions used by other modules
'''
#***************************************
# Imports
#***************************************
import os

import sqlite3

import re

from pathlib import Path

from dependencies.pefile import pefile

from support.utils import pebinarytype, dbgmsg

from support.utils import getpearch, ispedbgstripped, ispebuiltwithdebug

from support.utils import getpesigwoage, getpeage, getpepdbfilename

import globs

#***********************************************
# Functions
#***********************************************
def construct_tables(db_conn):
    '''
    construct_tables:
        db_conn: Database connection

    Description:
        Construct the initial SQLite DB tables
    '''
    dbcursor = db_conn.cursor()

    try:
        # Construct the PatchedFiles
        dbcursor.execute(
            "CREATE TABLE IF NOT EXISTS PatchedFiles " +
            "(FileName text, OperatingSystemVersion text, Architecture text," +
            " Signature text, SHA256 text, SHA512 text, Age integer, " +
            "PdbFilename text, DiskPath text, SymbolObtained integer, " +
            "SymbolPath text, FileExtension text, Type text, " +
            "OriginalFilename text, FileDescription text, ProductName text, " +
            "Comments text, CompanyName text, FileVersion text, " +
            "ProductVersion text, IsDebug integer, IsPatched integer, " +
            "IsPreReleased integer, IsPrivate integer, " +
            "IsSpecialBuild integer, Language text, PrivateBuild text, " +
            "SpecialBuild text, BuiltwithDbgInfo text, StrippedPE integer," +
            "UpdateId text, Ignored integer);")

        # Construct the UpdateFiles Table
        dbcursor.execute(
            "CREATE TABLE IF NOT EXISTS UpdateFiles " +
            "(FileName text, OperatingSystemVersion text, " +
            "Architecture text, Signature text, SHA256 text, SHA512 text, " +
            "CreationDate text, ModifiedDate text, " +
            "CategoryTypeCompany text, CategoryTypeProduct text, " +
            "CategoryTypeProductFamily text, " +
            "CategoryTypeUpdateClassification text, PackageType text, " +
            "Extracted integer, SymbolsObtained integer, IsSeceded integer, " +
            "SecededBy text, Language1 text, UpdateId text, " +
            "RevisionNumber integer, RevisionId integer, IsLeaf integer, " +
            "DiskPath text, FileId text, " +
            "OriginalFilename text, FileDescription text, ProductName text, " +
            "Comments text, CompanyName text, FileVersion text, " +
            "ProductVersion text, IsDebug integer, IsPatched integer, " +
            "IsPreReleased integer, IsPrivate integer, " +
            "IsSpecialBuild integer, PrivateBuild text, " +
            "SpecialBuild text, InsertionTime text);")

        # Construct the SymbolFiles Table
        dbcursor.execute(
            "CREATE TABLE IF NOT EXISTS SymbolFiles " +
            "(FileName text, Architecture text, Signature text, " +
            "SHA256 text, SHA512 text, " +
            "PublicSymbol integer, " +
            "PrivateSymbol integer, SymContains integer, " +
            "structSize integer, base integer, imageSize integer, " +
            "symDate integer, checksum integer, numsyms integer, " +
            "symtype text, modname text, imagename text, " +
            "loadedimage text, pdb text, CV text, CVDWORD integer, " +
            "CVData text, PDB20Sig text, PDB70Sig text, Age integer, " +
            "PDBMatched integer, DBGMatched integer, " +
            "LineNumber integer, Globalsyms integer, TypeInfo integer, " +
            "SymbolCheckVersionUsed integer, DbgFileName text, " +
            "DbgTimeDatestamp integer, DbgSizeOfTime integer, " +
            "DbgChecksum integer, PdbDbiAgeFullPdbFilename text, " +
            "PdbSignature text, PdbDbiAge integer, Source text, " +
            "Result integer, Ignored integer, IgnoredReason text, " +
            "SymbolObtained integer);")

        db_conn.commit()
        dbcursor.close()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        dbcursor.close()
        return False

    return True


def updatedbextractstat(extractedfile, status):
    '''
    update the extraction status
    '''
    dbname = globs.UPDATEFILESDBNAME
    dbcursor = globs.DBCONN.cursor()

    dbcursor.execute(
        "UPDATE " + dbname + " SET Extracted = ? WHERE FileName = ?",
        (int(status), str(extractedfile)))

    return True


def dbentryexist(dbcursor, dbname, sha256, sha512):
    '''
    check to see if particular hash already exists within db
    '''
    dbcursor.execute(
        "SELECT * FROM " + dbname + " WHERE " +
        "SHA256 = ? AND SHA512 = ?",
        (sha256, sha512))
    check = dbcursor.fetchone()

    if check is None:
        dbgmsg("[WSUS_DB] did not find " + sha256 + " entry in " + dbname)
        return False

    dbgmsg("[WSUS_DB] found " + sha256 + "entry in DB")
    return True

def dbentryexistwithsymbols(dbcursor, dbname, sha256, sha512):
    '''
    check to see if particular hash already exists within db and also if that
    entry has symbols already obtained for it
    '''
    dbcursor.execute(
        "SELECT * FROM " + dbname + " WHERE " +
        "SHA256 = ? AND SHA512 = ?",
        (sha256, sha512))
    check = dbcursor.fetchone()

    if check is None:
        dbgmsg("[WSUS_DB] did not find " + sha256 + " entry in " + dbname)
        return False

    if check["SymbolObtained"] == 0:
        return False

    dbgmsg("[WSUS_DB] found " + sha256 + "entry with symbols obtained in DB")
    return True

def symbolentryexist(dbcursor, dbname, signature, sha256, sha512):
    '''
    This function is invoked prior to obtaining symbols for a PE file
    to:
    1) identify current or previous PE files missing symbol information
        (no attempt to download symbols were performed yet)
    2) identify currently incomplete symbol information for a PE
        (no symbols were loaded)
    '''
    dbcursor.execute(
        "SELECT * FROM " + dbname + " WHERE " +
        "Signature = '" + signature + "' AND SHA256 = ? AND SHA512 = ?",
        (sha256, sha512))
    check = dbcursor.fetchone()

    if check is None:
        dbgmsg("[WSUS_DB] did not find " + signature + " entry in " + dbname)
        return False

    dbgmsg("[WSUS_DB] found " + signature + "entry in DB")
    return True

def parseline(locate, wholeline, offset=-1, digit=False, hexi=False):
    '''
    parse symchk output
    '''
    result = None
    try:
        if re.search(r"^\[SYMCHK\] \[ |^SYMCHK: ", wholeline):
            return result
        elif re.search(r"\[SYMCHK\] (Struct size:|Image size:)", wholeline):
            offset = -2
            digit = True
        elif re.search(r"\[SYMCHK\] (Checksum:|CV DWORD:|SymbolCheckVersion|Result|" +    \
            "DbgTimeDateStamp|DbgSizeOfImage|DbgSizeOfImage|DbgChecksum|" + \
            "PdbDbiAge|Date:)", wholeline):
            hexi = True
    except IndexError as ierror:
        dbgmsg("[WSUS_DB] {-} Parsing symchk output part 1: " + str(ierror) + " on " + wholeline)
        return result

    if locate in wholeline:
        result = str(wholeline.split()[offset])

        try:
            # No filename was given
            if re.search("^DbgFilename|^PdbFilename", result):
                result = ''

            if re.search(r"^\[SYMCHK\] Age:", wholeline):
                hexi = True
        except IndexError as ierror:
            dbgmsg("[WSUS_DB] {-} Parsing symchk output part 2: " + str(ierror) + " on " + wholeline)
            return None

        if "CV:" in wholeline:
            if result == "CV:":
                result = ""

        if digit:
            try:
                result = int(result)
            except ValueError as verror:
                dbgmsg("[WSUS_DB] {-} Caught: Converting " + str(result) + " from " + str(wholeline) +
                       " to an int. " + str(verror))
        elif hexi:
            try:
                result = int(result, 16)
            except ValueError as verror:
                dbgmsg("[WSUS_DB] {-} Caught: Converting " + str(result) + " from " + str(wholeline) +
                       " to an int. " + str(verror))

    return result

def writeupdate(file, sha256, sha512, \
        dbname=globs.UPDATEFILESDBNAME, conn=globs.DBCONN):
    '''
    @writeupdate
        file - absolute path to update file
    function to check database for existence of update before extracting.

    Just blindly "trusted" the CAB name
    OR
    Besides looking into capturing the CAB file's properties:
    1) verify the CAB files signature
    2) If trusted, use the filename and file extension to populate the table
        and correlation purposes.

    Additional information about the captured update file (i.e., CAB)
    can be found using the WID

    Since there is no clean way to get the properities

    file - update file to add or update db with
    sha256 - digest value (not hashlib object) of file
    sha512 - digest value (not hashlib object) of file
    seperated (mostly cannabalized) off from checkUpdates...
    '''
    from time import time

    packagetype = Path(file).suffix
    basename = os.path.basename(file)
    dbcursor = conn.cursor()
    dbgmsg("[WSUS_DB] is inserting new file and hash to updateDB")

    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 38 + "?)",
        # FileName, OperatingSystemVersion, Architecture, GUID, SHA256
        (basename, None, None, None, sha256,
         # SHA512, CreationDate, ModifiedDate, CategoryTypeCompnay
         # CategoryTypeProduct,
         sha512, None, None, None, None,
         # CategoryTypeProductFamily, CategoryTypeUpdateClassification,
         # PackageType, Extracted, SymbolsObtained
         None, None, packagetype, 0, 0,
         # IsSeceded, SecededBy, Language1, UpdateId, RevisionNumber
         0, None, None, None, None,
         # RevisionId, IsLeaf, DiskPath, FileId, OriginalFilename
         None, None, str(file), None, None,
         # FileDescritpion, ProductName, Comments, CompanyName,
         # FileVersion
         None, None, None, None, None,
         # ProductVersion, IsDebug, IsPatched, IsPreReleased, IsPrivate
         None, None, None, None, None,
         # IsSpecialBuild, PrivateBuild, SpecialBuild, InsertionTime
         None, None, None, str(time())))

    dbcursor.close()
    return True

def writebinary(file, sha256, sha512,  \
        dbname=globs.PATCHEDFILESDBNAME, conn=globs.DBCONN):
    '''
    file - update file to add or update db with
    sha256 - digest value (not hashlib object) of file
    sha512 - digest value (not hashlib object) of file

    function to check database for binary file before symchecking;
    updates database if already in existence
    '''
    basename = os.path.basename(file)
    arch = 'UNKNOWN'
    signature = 'UNKNOWN'
    age = -1
    pdbfilename = 'UNKNOWN'
    strippedpe = 0

    versionfields = {
        'OriginalFilename': '', 'FileDescription': '', 'ProductName': '',
        'Comments': '', 'CompanyName': '', 'FileVersion': '',
        'ProductVersion': '', 'IsDebug': '', 'IsPatched': '',
        'IsPreReleased': '', 'IsPrivateBuild': '', 'IsSpecialBuild': '',
        'Language': '', 'PrivateBuild': '', 'SpecialBuild': ''
    }

    try:
        unpefile = pefile.PE(file)
    except pefile.PEFormatError as peerror:
        dbgmsg("[WSUS_DB] skipping due to exception: " + peerror.value)
        return False

    dbgmsg("[WSUS_DB] !! Working on " + str(file))
    fileext, stype = pebinarytype(unpefile)
    arch = getpearch(unpefile)
    signature = getpesigwoage(unpefile)
    age = getpeage(unpefile)
    pdbfilename = getpepdbfilename(unpefile)
    strippedpe = ispedbgstripped(file)
    builtwithdbginfo = ispebuiltwithdebug(file)
    osver = "UNKNOWN"

    # Get the OS this PE is designed for ()
    # Microsoft PE files distributed via Microsoft's Update typically
    # use the ProductVersion file properties to indicate the OS the specific
    # PE file is built too.

    # a PE only have 1 VERSIONINFO, but multiple language strings
    # More information on different properites can be found at
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa381058
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa381049
    # convert below to the "dump()" ... try to use the "fixed" versioninfo

    versioninfo = getattr(unpefile, "VS_VERSIONINFO", None)
    if versioninfo is not None:
        fileinfo = getattr(unpefile, "FileInfo", None)
        if fileinfo is not None:
            for fileentry in unpefile.FileInfo:
                stringtable = getattr(fileentry, "StringTable", None)
                if stringtable is not None:
                    for strtable in fileentry.StringTable:
                        # Currently only handling unicode en-us
                        if strtable.LangID[:4] == b'0409' or \
                                (strtable.LangID[:4] == b'0000' and
                                 (strtable.LangID[4:] == b'04b0' or
                                  strtable.LangID[4:] == b'04B0')):
                            versionfields["Language"] \
                                = strtable.LangID.decode("utf-8")
                            for field, value in strtable.entries.items():
                                dfield = field.decode('utf-8')
                                dvalue = value.decode('utf-8')
                                if dfield == "OriginalFilename":
                                    versionfields["OriginalFilename"] \
                                        = dvalue
                                if dfield == "FileDescription":
                                    versionfields["FileDescription"] \
                                        = dvalue
                                if dfield == "ProductName":
                                    versionfields["ProductName"] \
                                        = dvalue
                                if dfield == "Comments":
                                    versionfields["Comments"] \
                                        = dvalue
                                if dfield == "CompanyName":
                                    versionfields["CompanyName"] \
                                        = dvalue
                                if dfield == "FileVersion":
                                    versionfields["FileVersion"] \
                                        = dvalue
                                if dfield == "ProductVersion":
                                    versionfields["ProductVersion"] \
                                        = dvalue
                                if dfield == "IsDebug":
                                    versionfields["IsDebug"] \
                                        = dvalue
                                if dfield == "IsPatched":
                                    versionfields["IsPatched"] \
                                        = dvalue
                                if dfield == "IsPreReleased":
                                    versionfields["IsPreReleased"] \
                                        = dvalue
                                if dfield == "IsPrivateBuild":
                                    versionfields["IsPrivateBuild"] \
                                        = dvalue
                                if dfield == "IsSpecialBuild":
                                    versionfields["IsSpecialBuild"] \
                                        = dvalue
                                if dfield == "PrivateBuild":
                                    versionfields["PrivateBuild"] \
                                        = dvalue
                                if dfield == "SpecialBuild":
                                    versionfields["SpecialBuild"] \
                                        = dvalue

    dbgmsg("[WSUS_DB] " + str(versionfields))

    # if this is a Microsoft binary the Product version is typically
    # the os version it was built for, but other products this is not
    # necessarily true
    # could "verify" Microsoft binary by signature of binary like with
    #  "trusting" Update file's name
    # Use the PE format to get the targeted OS version....
    if versionfields['ProductName'].find("Operating System") != -1:
        osver = "NT" + versionfields['ProductVersion']

    dbcursor = conn.cursor()

    dbgmsg("[WSUS_DB] inserting new file and hash")
    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 31 + "?)",
        # FileName,OperatingSystemVersion,Architecture,Signature,SHA256
        (basename, osver, arch, signature, sha256,
         # SHA512,Age,PdbFilename,DiskPath,SymbolObtained
         sha512, age, pdbfilename, str(file), 0,
         # SymbolPath,Type,FileExtension,OriginalFilename,FileDescription
         None, stype, fileext, versionfields['OriginalFilename'],
         versionfields['FileDescription'],
         # ProductName,Comments,CompanyName,FileVersion,ProductVersion,
         versionfields['ProductName'], versionfields['Comments'],
         versionfields['CompanyName'], versionfields['FileVersion'],
         versionfields['ProductVersion'],
         # IsDebug,IsPatched,IsPreReleased,IsPrivateBuild,IsSpecialBuild,
         versionfields['IsDebug'], versionfields['IsPatched'],
         versionfields['IsPreReleased'],
         versionfields['IsPrivateBuild'],
         versionfields['IsSpecialBuild'],
         # Language,PrivateBuild
         versionfields['Language'], versionfields['PrivateBuild'],
         # SpecialBuild,BuiltwithDbgInfo,StrippedPE,UpdateId,Ignored
         versionfields['SpecialBuild'], str(builtwithdbginfo), int(strippedpe), None, int(False)))

    dbcursor.close()
    unpefile.close()
    return True

def writesymbol(file, symchkerr, symchkout, sha256, sha512, \
        dbname=globs.SYMBOLFILESDBNAME, conn=globs.DBCONN):
    '''
    The fields taken from symchk.exe are taken from:
    MSDN docs - _IMAGEHLP_MODULE64 structure -
    https://docs.microsoft.com/en-us/windows/desktop/api/dbghelp/ns-dbghelp-_imagehlp_module64
    '''
    basename = os.path.basename(file)
    dbcursor = conn.cursor()
    ignored = False
    signature = ''
    symcontains = 'UNKNOWN'
    public = False
    private = False
    unpefile = None
    ignoredreason = 'None'

    try:
        unpefile = pefile.PE(file)
    except pefile.PEFormatError as peerror:
        dbgmsg("[WSUS_DB] Caught: PE error " + str(peerror) + ". File: " + file)
        return False

    arch = getpearch(unpefile)

    symchkarr = {
        "Struct size:": '',
        "Base:": 0,
        "Image size:": 0,
        "Date:": 0,
        "Checksum:": 0,
        "NumSyms:": '',
        "SymType:": '',
        "ModName:": '',
        "ImageName:": '',
        "LoadedImage:": '',
        "PDB:": '',
        "CV:": '',
        "CV DWORD:": 0,
        "CV Data:": '',
        "PDB Sig:": '',
        "PDB7 Sig:": '',
        "Age:": 0,
        "PDB Matched:": '',
        "DBG Matched:": '',
        "Line nubmers:": '',
        "Global syms:": '',
        "Type Info:": '',
        "SymbolCheckVersion": 0,
        "Result": 0,
        "DbgFilename": '',
        "DbgTimeDateStamp": 0,
        "DbgSizeOfImage": 0,
        "DbgChecksum": 0,
        "PdbFilename": '',
        "PdbSignature": '',
        "PdbDbiAge": 0
        }

    for line in symchkerr:
        try:
            if re.search("^DBGHELP: " + basename.split('.')[0] + " - ", line):
                symcontains = line.split("- ")[1]
                if re.search("public", symcontains):
                    public = True
                elif re.search("private", symcontains):
                    private = True
        except IndexError as ierror:
            dbgmsg("[WSUS_DB] {-} Parsing symchk output DBGHELP: " + str(ierror) + " on " + file)
            continue

        for field in symchkarr:
            result = parseline(field, line)
            if result is not None:
                symchkarr[field] = result

        line = None

    try:
        if re.search(" IGNORED  -", symchkout[-5]):
            ignored = True
            ignoredreason = symchkout[-5].split("  - ")[1]

            # If a PE file is ignored, symchk.exe will not provide any unique information
            # about the PE file (i.e., Signature). Therefore, we extract the
            # Signature (GUID) from the PE ourselves
            signature = getpesigwoage(unpefile)
        else:
            if symchkarr["PDB7 Sig:"] != '' and \
            symchkarr["PDB7 Sig:"] != '{00000000-0000-0000-0000-000000000000}':
                signature = symchkarr["PDB7 Sig:"]
            elif symchkarr["PDB Sig:"] != '':
                signature = symchkarr["PDB Sig:"]
    except IndexError as ierror:
        dbgmsg("[WSUS_DB] {-} Parsing symchk output IGNORED: " + str(ierror) + " on " + file)
        return False

    if symchkarr["SymType:"] == "SymNone":
        source = ''
    else:
        source = symchkerr[-1]

    dbgmsg("[WSUS_DB] is inserting new file and hash to symbolDB")

    symbolobtained = int(False)

    # update PatchedFile table (symbol obtained and ignored status)
    if int(public) != 0 or int(private) != 0:
        symbolobtained = int(True)

        dbcursor.execute(("UPDATE " + globs.PATCHEDFILESDBNAME +    \
            " SET SymbolObtained = " +                              \
            "{} WHERE Signature = '{}'").format(symbolobtained, signature))

        dbcursor.execute(("UPDATE " + globs.PATCHEDFILESDBNAME + \
            " SET SymbolPath = '{}' WHERE " + \
            "Signature = '{}'").format(symchkarr["PDB:"], signature))

    if ignored:
        dbcursor.execute("UPDATE " + globs.PATCHEDFILESDBNAME + \
            " SET Ignored = {} WHERE Signature = '{}'".format(int(ignored), signature))

    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 42 + "?)",
        # FileName, Architecture, Signature, SHA256
        (basename, arch, signature, sha256,
         # SHA512, PublicSymbol, PrivateSymbol
         sha512, int(public), int(private),
         # SymbolContains, structSize, base, imagesize, symDate
         symcontains, symchkarr["Struct size:"], symchkarr["Base:"],
         symchkarr["Image size:"], symchkarr["Date:"],
         # checksum (int), numsyms (int), symtype, modname, imagename
         symchkarr["Checksum:"], symchkarr["NumSyms:"],
         symchkarr["SymType:"], symchkarr["ModName:"],
         symchkarr["ImageName:"],
         # loadedimage, pdb, CV, CVDWORD, CVData
         symchkarr["LoadedImage:"], symchkarr["PDB:"],
         symchkarr["CV:"], symchkarr["CV DWORD:"],
         symchkarr["CV Data:"],
         # PDBSig, PDB7Sig, Age, PDBMatched, DBGMatched
         symchkarr["PDB Sig:"], symchkarr["PDB7 Sig:"],
         symchkarr["Age:"],
         symchkarr["PDB Matched:"], symchkarr["DBG Matched:"],
         # LineNumber, Globalsyms, TypeInfo, SymbolCheckVersionUsed,
         # DbgFileName
         symchkarr["Line nubmers:"], symchkarr["Global syms:"],
         symchkarr["Type Info:"], symchkarr["SymbolCheckVersion"],
         symchkarr['DbgFilename'],
         # DbgTimeDatestamp, DbgSizeOfTime
         symchkarr['DbgTimeDateStamp'],
         symchkarr["DbgSizeOfImage"],
         # DbgChecksum, PdbDbiAgeFullPdbFilename, PdbSignature,
         # PdbDbiAge
         symchkarr["DbgChecksum"],
         symchkarr["PdbFilename"],
         symchkarr["PdbSignature"],
         symchkarr["PdbDbiAge"],
         # Source, Result, Ignored, IgnoredReason,
         source, symchkarr["Result"], int(ignored), ignoredreason,
         #SymbolObtained
         symbolobtained))

    unpefile.close()

    dbcursor.close()
    return True

def starttransaction(conn=globs.DBCONN):
    '''
    start transations
    '''
    dbcursor = conn.cursor()
    dbcursor.execute("BEGIN TRANSACTION")
    dbcursor.close()

def endtransaction(conn=globs.DBCONN, final=False):
    '''
    end transations
    '''
    dbcursor = conn.cursor()
    dbcursor.execute("END TRANSACTION")
    if not final:
        dbcursor.execute("BEGIN TRANSACTION")
    dbcursor.close()
    