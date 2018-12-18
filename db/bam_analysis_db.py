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

def prodvgtebyname(dbcursor, filename, prodversion):
    '''
    Find any entries that is gte to argument
    '''

    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}' AND ProductVersion >= '{}'").format(str(filename), str(prodversion)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvgtebyname")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvgtebyname")
    return result

def prodvltebyname(dbcursor, filename, prodversion):
    '''
    Find any entries that is lte to argument
    '''

    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}' AND ProductVersion <= '{}'").format(str(filename), str(prodversion)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvltebyname")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvltebyname")
    return result

def prodvltbyname(dbcursor, filename, prodversion):
    '''
    Find any entries that is lt to argument
    '''

    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}' AND ProductVersion < '{}'").format(str(filename), str(prodversion)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvltebyname")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvltebyname")
    return result

def prodvgtbyname(dbcursor, filename, prodversion):
    '''
    Find any entries that is gt to argument
    '''

    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}' AND ProductVersion > '{}'").format(str(filename), str(prodversion)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvgtbyname")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvgtbyname")
    return result

def prodvebyname(dbcursor, filename, prodversion):
    '''
    Find any entries that is e to argument
    '''

    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}' AND ProductVersion = '{}'").format(str(filename), str(prodversion)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from prodvebyname")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from prodvebyname")
    return result

def wusamefn(dbcursor, filename):
    '''
    Retrieve list of Windows Updates that distribute the same filename
    '''
    global _wdblogger

    dbcursor.execute(
        ("SELECT * FROM " + globs.PATCHEDFILESDBNAME + " WHERE " +
        "FileName = '{}'").format(str(filename)))

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from wusamefn")
        return None

    _wdblogger.log(logging.DEBUG, "[BAMA] Found entries from wusamefn")
    return result

def getpathtoupdate(dbcursor, filedigest):

    global _wdblogger

    hexfiledigest = verifyhex(filedigest)
    
    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getpathtoupdate")
        return hexfiledigest

    # Verify file is available

    sql = ("SELECT * FROM " + globs.UPDATEFILESDBNAME + " WHERE " +
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


def getwuwithsamefnprodv(dbcursor, filename, prodversion):
    '''
    Retrieve list of Windows Updates that distribute the same filename and ProductVersion E
    '''
    global _wdblogger

    filelist = prodvebyname(dbcursor, filename, prodversion)

    if filelist == None:
        return filelist

    updatelist = []

    for row in filelist:
        for column in row.keys():
            if column == "UpdateId":
                updatelist.append(row[column])

    return updatelist

def getwuwithsamefnprodvgt(dbcursor, filename, prodversion):
    '''
    Retrieve list of Windows Updates that distribute the same filename and ProductVersion GT
    '''
    global _wdblogger

    filelist = prodvgtbyname(dbcursor, filename, prodversion)

    if filelist == None:
        return filelist

    updatelist = []

    for row in filelist:
        for column in row.keys():
            if column == "UpdateId":
                updatelist.append(row[column])

    return updatelist


def getwuwithsamefnprodvlt(dbcursor, filename, prodversion):
    '''
    Retrieve list of Windows Updates that distribute the same filename and ProductVersion LT
    '''
    global _wdblogger

    filelist = prodvltbyname(dbcursor, filename, prodversion)

    if filelist == None:
        return filelist

    updatelist = []

    for row in filelist:
        for column in row.keys():
            if column == "UpdateId":
                updatelist.append(row[column])

    return updatelist

def getwuwithsamefnprodvlte(dbcursor, filename, prodversion):
    '''
    Retrieve list of Windows Updates that distribute the same filename and ProductVersion LTE
    '''
    global _wdblogger

    filelist = prodvltebyname(dbcursor, filename, prodversion)

    if filelist == None:
        return filelist

    updatelist = []

    for row in filelist:
        for column in row.keys():
            if column == "UpdateId":
                updatelist.append(row[column])

    return updatelist

def getwuwithsamefnprodvgte(dbcursor, filename, prodversion):
    '''
    Retrieve list of Windows Updates that distribute the same filename and ProductVersion GTE
    '''
    global _wdblogger

    filelist = prodvgtebyname(dbcursor, filename, prodversion)

    if filelist == None:
        return filelist

    updatelist = []

    for row in filelist:
        for column in row.keys():
            if column == "UpdateId":
                updatelist.append(row[column])

    return updatelist

def getlistofpublicsym(dbcursor, filename):
    '''
    Retrieve list of all unique public symbols PDBs with filename
    '''
    global _wdblogger

    dbcursor.execute(("SELECT * FROM " + globs.SYMBOLFILESDBNAME + " "
                    "WHERE FileName = '{}' AND PublicSymbol = 1").format(filename) )

    result = dbcursor.fetchall()

    if len(result) == 0:
        _wdblogger.log(logging.DEBUG, "[BAMA] Did not find entries from wusamefn")
        return None
    
    return result
