'''
Microsoft's Security Development Lifecycle (SDL) Banned Function Calls - https://msdn.microsoft.com/library/bb288454.aspx
https://github.com/x509cert/banned/blob/master/banned.h - By/hosted Michael Howard - Microsoft Employee 

'''
import re

import os

import sqlite3

import subprocess

import logging, logging.handlers

import BamLogger

from time import time

from pathlib import Path

from support.utils import getfilehashes, rmfile

from globs import BANNEDTABLE, DBCONN2

import pefile

_pbanlogger = logging.getLogger("BAM.post_banned")

def pbanned_logconfig(queue):
    global _pbanlogger

    qh = logging.handlers.QueueHandler(queue)
    _pbanlogger.addHandler(qh)
    _pbanlogger.setLevel(logging.DEBUG)

def getbannedapis():
    global _pbanlogger

    bannedapis = None
    try:
        with open(".\\tools\\x64\\banned.h") as fbanned:
            all_lines = fbanned.readlines()
            linesjoined = ''.join(all_lines)
            bannedfound = re.findall(r'pragma deprecated \((.*)\)', linesjoined)
            bannedapis = sorted(set(', '.join(bannedfound).split(', ')))
    except FileNotFoundError as dummy:
        logmsg = ("[PBAN] {-} Skipping insertion into DB. banned.h not found.")
        _pbanlogger.log(logging.DEBUG, logmsg)
    
    return bannedapis


def findbannedapis(file):
    global _pbanlogger

    _pbanlogger.log(logging.DEBUG, "[PBAN] Working on " + file + " for Banned APIs verification")

    bannedapis = getbannedapis()

    if bannedapis is None:
        logmsg = ("[PBAN] {-} Skipping Banned Analysis.")
        _pbanlogger.log(logging.DEBUG, logmsg)
        return

    basename = os.path.basename(file)

    pe_file = None

    try:
        pe_file = pefile.PE(file)
    except pe_file.PEFormatError as peerror:
        logmsg = ("[PBAN] {-} Skipping DB insertion. Issue with handling PE file" + str(peerror.value))
        _pbanlogger.log(logging.DEBUG, logmsg)
        return

    hashes = getfilehashes(file)

    if hashes is None:
        _pbanlogger.log(logging.DEBUG, "[PBSK] Error getting hashes for " + file)
        return

    dbcursor = DBCONN2.cursor()

    dbcursor.execute("BEGIN TRANSACTION")

    if hasattr(pe_file, 'DIRECTORY_ENTRY_IMPORT'):
        for module in pe_file.DIRECTORY_ENTRY_IMPORT:
            for importm in module.imports:
                if importm.name is not None and importm.name.decode('ascii') in bannedapis:
                    mname = module.dll.decode('ascii')
                    fn = importm.name.decode('ascii')

                    try:
                        dbcursor.execute(
                            "INSERT INTO " + "BannedApiFiles" + " VALUES (" + "?," * 5 + "?)",
                            # FileName, SHA256, SHA1, ModuleName, BannedApiUsed
                            (basename, hashes[0], hashes[1], mname, fn,
                            # timestamp
                            str(time())))

                    except sqlite3.Error as error:
                        _pbanlogger.log(logging.DEBUG, ("[PBSK] INSERT ConfigurationNotifications error (incomplete): " + error.args[0]))
    
    dbcursor.execute("END TRANSACTION")
    _pbanlogger.log(logging.DEBUG, ("[PBAN] Completed "+ file))

    dbcursor.close()