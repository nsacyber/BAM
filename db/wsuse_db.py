'''
This module contains the various database management functions used by other modules
'''
#***************************************
# Imports
#***************************************
import os

import sqlite3

import re

import logging, logging.handlers

from pathlib import Path

from dependencies.pefile import pefile

from support.utils import pebinarytype

from support.utils import getpearch, ispedbgstripped, ispebuiltwithdebug

from support.utils import getpesigwoage, getpeage, getpepdbfilename

import globs

import BamLogger

#***********************************************
# Local Variables
#***********************************************
_wdblogger = logging.getLogger("BAM.wsuse_db")

def db_logconfig(queue):
    global _wdblogger

    qh = logging.handlers.QueueHandler(queue)
    _wdblogger.addHandler(qh)
    _wdblogger.setLevel(logging.DEBUG)

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
        dbcursor.execute(globs.PATCHEDFILETSTMT)

        # Construct the UpdateFiles Table
        dbcursor.execute(globs.UPDATEFILETSTMT)

        # Construct the SymbolFiles Table
        dbcursor.execute(globs.SYMBOLFILETSTMT)

        db_conn.commit()
        dbcursor.close()
    except sqlite3.Error as error:
        print("Caught: " + error.args[0])
        dbcursor.close()
        return False

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

    global _wdblogger

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WSUS_DB] did not find " + sha256 + " entry in " + dbname)
        return False

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] found " + sha256 + "entry in DB")
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

    global _wdblogger

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WSUS_DB] did not find " + sha256 + " entry in " + dbname)
        return False

    if check["SymbolObtained"] == 0:
        return False

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] found " + sha256 + "entry with symbols obtained in DB")
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

    global _wdblogger

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WSUS_DB] did not find " + signature + " entry in " + dbname)
        return False

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] found " + signature + "entry in DB")
    return True

def parseline(locate, wholeline, offset=-1, digit=False, hexi=False):
    '''
    parse symchk output
    '''
    global _wdblogger

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
        _wdblogger.log(logging.DEBUG, "[WSUS_DB] {-} Parsing symchk output part 1: " + str(ierror) + " on " + wholeline)
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
            _wdblogger.log(logging.DEBUG, "[WSUS_DB] {-} Parsing symchk output part 2: " + str(ierror) + " on " + wholeline)
            return None

        if "CV:" in wholeline:
            if result == "CV:":
                result = ""

        if digit:
            try:
                result = int(result)
            except ValueError as verror:
                _wdblogger.log(logging.DEBUG, "[WSUS_DB] {-} Caught: Converting " + str(result) + " from " + str(wholeline) +
                        " to an int. " + str(verror))
                pass
        elif hexi:
            try:
                result = int(result, 16)
            except ValueError as verror:
                _wdblogger.log(logging.DEBUG, "[WSUS_DB] {-} Caught: Converting " + str(result) + " from " + str(wholeline) +
                       " to an int. " + str(verror))
                pass

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

    global _wdblogger
    basename = os.path.basename(file)
    dbcursor = conn.cursor()
    _wdblogger.log(logging.DEBUG, "[WSUS_DB] is inserting new file and hash to updateDB")

    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 8 + "?)",
        # FileName, SHA256
        (basename, sha256,
         # SHA512,
         sha512,
         # Extracted, SymbolsObtained
         1, 0,
         # WasSeceded, SecededBy,
         0, None,
         # DiskPath,
         str(file),
         # InsertionTime
         str(time())))

    dbcursor.close()
    return True

def writebinary(file, sha256, sha512, infolist,  \
        dbname=globs.PATCHEDFILESDBNAME, conn=globs.DBCONN):
    '''
    file - update file to add or update db with
    sha256 - digest value (not hashlib object) of file
    sha512 - digest value (not hashlib object) of file

    function to check database for binary file before symchecking;
    updates database if already in existence
    '''
    basename = os.path.basename(file)
    global _wdblogger

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] !! Working on ")
    _wdblogger.log(logging.DEBUG, "[WSUS_DB] " + str(infolist))

    dbcursor = conn.cursor()

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] inserting new file and hash")
    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 31 + "?)",
        # FileName,OperatingSystemVersion,Architecture,Signature,SHA256
        (basename, infolist['osver'], infolist['arch'], infolist['signature'], sha256,
         # SHA512,Age,PdbFilename,DiskPath,SymbolObtained
         sha512, infolist['age'], infolist['pdbfilename'], str(file), 0,
         # SymbolPath,Type,FileExtension,OriginalFilename,FileDescription
         None, infolist['stype'], infolist['fileext'], infolist['OriginalFilename'],
         infolist['FileDescription'],
         # ProductName,Comments,CompanyName,FileVersion,ProductVersion,
         infolist['ProductName'], infolist['Comments'],
         infolist['CompanyName'], infolist['FileVersion'],
         infolist['ProductVersion'],
         # IsDebug,IsPatched,IsPreReleased,IsPrivateBuild,IsSpecialBuild,
         infolist['IsDebug'], infolist['IsPatched'],
         infolist['IsPreReleased'],
         infolist['IsPrivateBuild'],
         infolist['IsSpecialBuild'],
         # Language,PrivateBuild
         infolist['Language'], infolist['PrivateBuild'],
         # SpecialBuild,BuiltwithDbgInfo,StrippedPE,UpdateId,Ignored
         infolist['SpecialBuild'], str(infolist['builtwithdbginfo']), int(infolist['strippedpe']), None, int(False)))

    dbcursor.close()
    return True

def writesymbol(file, symchkerr, symchkout, sha256, sha512, infolist, \
        exdest, dbname=globs.SYMBOLFILESDBNAME, conn=globs.DBCONN):
    '''
    The fields taken from symchk.exe are taken from:
    MSDN docs - _IMAGEHLP_MODULE64 structure -
    https://docs.microsoft.com/en-us/windows/desktop/api/dbghelp/ns-dbghelp-_imagehlp_module64
    '''
    basename = os.path.basename(file)
    dbcursor = conn.cursor()
    ignored = False
    symcontains = 'UNKNOWN'
    public = False
    private = False
    ignoredreason = 'None'

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
    global _wdblogger

    for line in symchkerr:
        try:
            if re.search("^DBGHELP: " + basename.split('.')[0] + " - ", line):
                symcontains = line.split("- ")[1]
                if re.search("public", symcontains):
                    public = True
                elif re.search("private", symcontains):
                    private = True
        except IndexError as ierror:
            _wdblogger.log(logging.DEBUG, "[WSUS_DB] {-} Parsing symchk output DBGHELP: " + str(ierror) + " on " + file)
            continue

        for field in symchkarr:
            result = parseline(field, line)
            if result is not None:
                symchkarr[field] = result

        line = None

    if re.search(" IGNORED  -", symchkout[-5]):
        ignored = True
        ignoredreason = symchkout[-5].split("  - ")[1]

    if symchkarr["SymType:"] == "SymNone":
        source = ''
    else:
        source = symchkerr[-1]

    _wdblogger.log(logging.DEBUG, "[WSUS_DB] is inserting new file and hash to symbolDB")

    symbolobtained = int(False)

    # update PatchedFile table (symbol obtained and ignored status)
    if int(public) != 0 or int(private) != 0:
        symbolobtained = int(True)

        dbcursor.execute(("UPDATE " + globs.PATCHEDFILESDBNAME +    \
            " SET SymbolObtained = " +                              \
            "{} WHERE SHA256 = '{}' AND Signature = '{}'").format(symbolobtained, sha256, infolist['signature']))

        dbcursor.execute(("UPDATE " + globs.PATCHEDFILESDBNAME + \
            " SET SymbolPath = '{}' WHERE " + \
            "SHA256 = '{}' AND Signature = '{}'").format(symchkarr["PDB:"], sha256, infolist['signature']))

        base = os.path.basename(exdest)
        uindex = 0

        for index, x in enumerate(symchkarr["ImageName:"].split("\\")):
            if x == base:
                uindex = index+1

        updateid = symchkarr["ImageName:"].split("\\")[uindex]

        dbcursor.execute(("UPDATE " + globs.PATCHEDFILESDBNAME + \
            " SET UpdateId = '{}' WHERE " + \
            "SHA256 = '{}' AND Signature = '{}'").format(updateid, sha256, infolist['signature']))

    if ignored:
        dbcursor.execute("UPDATE " + globs.PATCHEDFILESDBNAME + \
            " SET Ignored = {} WHERE SHA256 = '{}' AND Signature = '{}'".format(int(ignored), sha256, infolist['signature']))

    dbcursor.execute(
        "INSERT INTO " + dbname + " VALUES (" + "?," * 42 + "?)",
        # FileName, Architecture, Signature, SHA256
        (basename, infolist['arch'], infolist['signature'], sha256,
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
    