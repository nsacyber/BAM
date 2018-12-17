#! python3

# ************************************************************
# Imports
# ************************************************************
import sys

import csv

import sqlite3

# Verify Python version
if sys.version_info[0] <= 3 and sys.version_info[1] < 7:
    sys.exit("This script requires at least Python version 3.7.")

from importlib import util

pyodbc_spec = util.find_spec("pyodbc")
if pyodbc_spec is None:
    sys.exit("Requires Python SQL Driver (pyodbc) - https://docs.microsoft.com/en-us/sql/connect/python/pyodbc/python-sql-driver-pyodbc?view=sql-server-2017")

import pyodbc

import globs

import argparse

import sqlite3

from support.utils import exitfunction, util_logconfig

from wuapis import getsupersedingfromfile, getfiledigestattributes, getfileattrbyfnprodv, findupdate, getKBtofiledigest, getKBoffiledigest

from wuapis import findfileswithkb, getsupersededfromfiledigest, getsupersededfromfiledigest_custom

import BamLogger

try:
    DBWSUSCONN = pyodbc.connect(globs.connstr)
except pyodbc.OperationalError as error:
    print(error)
    sys.exit("Must be able to connect to WSUS")

def displayhelp(parserh):
    '''
    displays help prompt
    '''
    parserh.print_help()

def parsecommandline(parser):
    '''
    parses arguments given to commandline
    '''
    parser.add_argument(
        "-wu", "--winupdateinfo", 
        help="Optional (Requires pyodbc)."
        "should be added to database.",
        action='store_true')
    if len(sys.argv) == 1:
        displayhelp(parser)
        exitfunction()

    return parser.parse_args()



if __name__ == "__main__":    

    PARSER = argparse.ArgumentParser()
    ARGS = parsecommandline(PARSER)

    if ARGS.winupdateinfo:
        try:
            print("Connected to: " + globs.connstr)

            '''
            EMPTY
            '''
           
        except sqlite3.Error as error:
            print("Error caught: ", error.args[0])
        except Exception as e:
            print("Error caught", str(e))
    
    globs.DBCONN.close()
    globs.DBWSUSCONN.close()
