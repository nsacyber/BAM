'''
this file contains global values and variables used throughout the application
'''
#***************************************
# Imports
#***************************************
import sqlite3
import multiprocessing as mp
from importlib import util
#***************************************
# Global Constants
#***************************************
# shared connection to db
DBCONN = sqlite3.connect("WSUS_Update_Data.db",
                         check_same_thread=False, isolation_level=None)

DBWSUSCONN = None

DBCONN.execute("pragma journal_mode=wal")
DBCONN.execute("pragma synchronous=NORMAL")

# WSUS-related
server = 'np:\\\\.\\pipe\\MICROSOFT##WID\\tsql\\query'
database = 'SUSDB'
connstr = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER='+server+';DATABASE='+database+';'

# to view column names
DBCONN.row_factory = sqlite3.Row
# table names
UPDATEFILESDBNAME = "UpdateFiles"
SYMBOLFILESDBNAME = "SymbolFiles"
PATCHEDFILESDBNAME = "PatchedFiles"

PATCHEDFILETSTMT = ("CREATE TABLE IF NOT EXISTS PatchedFiles " +
    "(FileName text, OperatingSystemVersion text, Architecture text," +
    " Signature text, SHA256 text, SHA1 text, Age integer, " +
    "PdbFilename text, DiskPath text, SymbolObtained integer, " +
    "SymbolPath text, FileExtension text, Type text, " +
    "OriginalFilename text, FileDescription text, ProductName text, " +
    "Comments text, CompanyName text, FileVersion text, " +
    "ProductVersion text, IsDebug integer, IsPatched integer, " +
    "IsPreReleased integer, IsPrivate integer, " +
    "IsSpecialBuild integer, Language text, PrivateBuild text, " +
    "SpecialBuild text, BuiltwithDbgInfo text, StrippedPE integer," +
    "UpdateId text, Ignored integer);")

UPDATEFILETSTMT = ("CREATE TABLE IF NOT EXISTS UpdateFiles " +
    "(FileName text, " +
    "SHA256 text, SHA1 text, " +
    "Extracted integer, SymbolsObtained integer, Seceding text, " +
    "SecededBy text, " +
    "DiskPath text, " +
    "InsertionTime text);")

SYMBOLFILETSTMT = ("CREATE TABLE IF NOT EXISTS SymbolFiles " +
    "(FileName text, Architecture text, Signature text, " +
    "SHA256 text, SHA1 text, " +
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

# enable or disable debug output
VERBOSITY = False

GLOBQUEUE = mp.Queue(-1)
