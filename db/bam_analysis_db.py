#***************************************
# Imports
#***************************************
import os

import sqlite3

import re

import logging, logging.handlers

from pathlib import Path

from dependencies.pefile import pefile

from support.utils import pebinarytype, getfilehashes

from support.utils import getpearch, ispedbgstripped, ispebuiltwithdebug

from support.utils import getpesigwoage, getpeage, getpepdbfilename, verifyhex

import globs

import BamLogger

_wdblogger = logging.getLogger("BAM.bam_analysis_db")

def db_logconfig(queue):
    global _wdblogger

    qh = logging.handlers.QueueHandler(queue)
    _wdblogger.addHandler(qh)
    _wdblogger.setLevel(logging.DEBUG)

'''
Retrieve PE files based off Product Version captured from PE file.
Support: Microsoft Products only.
'''

def prodvgtebyname(dbcursor, filename, prodversion, dbname=globs.PATCHEDFILESDBNAME):
    '''
    Find any entries that is gte to argument
    '''

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}' AND ProductVersion >= '{}'").format(str(filename), str(prodversion)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvgtebyname")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvgtebyname")
    return result

def prodvltebyname(dbcursor, filename, prodversion, dbname=globs.PATCHEDFILESDBNAME):
    '''
    Find any entries that is lte to argument
    '''

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}' AND ProductVersion <= '{}'").format(str(filename), str(prodversion)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvltebyname")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvltebyname")
    return result

def prodvltbyname(dbcursor, filename, prodversion, dbname=globs.PATCHEDFILESDBNAME):
    '''
    Find any entries that is lt to argument
    '''

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}' AND ProductVersion < '{}'").format(str(filename), str(prodversion)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvltebyname")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvltebyname")
    return result

def prodvgtbyname(dbcursor, filename, prodversion, dbname=globs.PATCHEDFILESDBNAME):
    '''
    Find any entries that is gt to argument
    '''

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}' AND ProductVersion > '{}'").format(str(filename), str(prodversion)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvgtbyname")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvgtbyname")
    return result

def prodvebyname(dbcursor, filename, prodversion, dbname=globs.PATCHEDFILESDBNAME):
    '''
    Find any entries that is e to argument
    '''

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}' AND ProductVersion = '{}'").format(str(filename), str(prodversion)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvebyname")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvebyname")
    return result


'''
Retrieve list of Windows Updates that distribute the same filename
'''
def wusamefn(dbcursor, filename, dbname=globs.PATCHEDFILESDBNAME):

    global _wdblogger

    check = dbcursor.execute(
        ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}'").format(str(filename)))

    if check is None:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from wusamefn")
        return check

    result = dbcursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from wusamefn")
    return result

def getpathtoupdate(dbcursor, filedigest, dbname=globs.UPDATEFILESDBNAME):

    global _wdblogger

    hexfiledigest = verifyhex(filedigest)
    
    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getpathtoupdate")
        return hexfiledigest


    # Verify file is available

    sql = ("SELECT * FROM " + dbname + " WHERE " +
        "FileName = '{}'").format(hexfiledigest[2:])

    dbcursor.execute(sql)
    result = dbcursor.fetchall()
    
    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from getpathtoupdate")
        return None

    diskpath = ""
    for row in result:
        for column in row.keys():
            if column == "DiskPath":
                diskpath = row[column]

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getpathtoupdate")
    return diskpath