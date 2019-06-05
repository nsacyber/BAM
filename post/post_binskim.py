import json

import sqlite3

import os.path

import subprocess

import logging, logging.handlers

import BamLogger

from time import time

from pathlib import Path

from support.utils import getfilehashes, rmfile

from globs import BINSKIMTABLE, DBCONN2

_bsklogger = logging.getLogger("BAM.post_binskim")

def binskim_logconfig(queue):
    global _bsklogger

    qh = logging.handlers.QueueHandler(queue)
    _bsklogger.addHandler(qh)
    _bsklogger.setLevel(logging.DEBUG)

def constructSarifMsg(ruleid, messageId, msgargs, jsonobj):
    global _bsklogger

    sarifmsg = ''
    try:
        sarifmsg = str(jsonobj["runs"][0]["resources"]["rules"][ruleid]["messageStrings"][messageId]).format(*msgargs)
    except Exception as error:
        _bsklogger.log(logging.DEBUG, "[PBSK] " + str(error))
        return sarifmsg
    
    return sarifmsg

def binskimanalysis(file, sympath):
    global _bsklogger

    _bsklogger.log(logging.DEBUG, "[PBSK] Working on " + file + " with symservr (" + sympath + ")")

    vsympath = Path(sympath)
    vfile = Path(file)
    if not vsympath.exists():
        _bsklogger.log(logging.DEBUG, "[PBSK] Provided symbol path (" + sympath + ") does not exist. Skipping " + file)
        return
    elif not vfile.is_file():
        _bsklogger.log(logging.DEBUG, "[PBSK] Provided file (" + file + ") does not exist. Skipping.....")
        return

    strtime = str(time())
    basename = os.path.basename(file)
    bskjson = "_" + basename + "_" + strtime + "_binskim.json"
    
    args = (".\\tools\\x64\\\\binskim\\binskim.exe analyze \"" + file +
    "\" --verbose --sympath \"Cache*" + sympath + "\" -o \"" + bskjson + "\" -p -f" )
    
    _bsklogger.log(logging.DEBUG, "[PBSK] Starting: " + args)
    
    try:
        with subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as pbinskim:
            dummy = pbinskim.communicate()
    except subprocess.CalledProcessError as error:
        logmsg = ("[PBSK] {-} BinSkim failed with error: " + str(error.returncode) + 
                ". File: " + file)
        _bsklogger.log(logging.DEBUG, logmsg)
        return
    except FileNotFoundError as error:
        logmsg = ("[PBSK] {-} BinSkim.exe not found")
        _bsklogger.log(logging.DEBUG, logmsg)
        return
    
    hashes = getfilehashes(file)

    if hashes is None:
        _bsklogger.log(logging.DEBUG, "[PBSK] Error getting hashes for " + file)
        return

    count  = 0

    dbcursor = DBCONN2.cursor()

    dbcursor.execute("BEGIN TRANSACTION")

    try:
        with open(bskjson) as data_file:    
            data = None
            try:
                data = json.load(data_file)
            except json.decoder.JSONDecodeError as error:
                _bsklogger.log(logging.DEBUG, ("[PBSK] JSON error: " + error.msg))
                dbcursor.execute("END TRANSACTION")
                dbcursor.close()
                return

            for entry in data["runs"][0]["results"]:
                if entry["ruleId"][:3] != "BA3":
                    # ignore ELF rules
                    msg = constructSarifMsg(entry["ruleId"], 
                    entry["message"]["messageId"], 
                    entry["message"]["arguments"], data)
                    
                    try:
                        dbcursor.execute(
                            "INSERT INTO " + "BinSkimfiles" + " VALUES (" + "?," * 7 + "?)",
                            # FileName, SHA256, SHA1, RuleId, Result
                            (basename, hashes[0], hashes[1], entry["ruleId"], entry["level"],
                            # MessageId, Message
                            entry["message"]["messageId"], msg,
                            # time
                            strtime))
                        count = count + 1
                    except sqlite3.Error as error:
                        _bsklogger.log(logging.DEBUG, ("[PBSK] INSERT Rules error (incomplete): " + error.args[0]))

            for entry in data["runs"][0]["invocations"]:
                try:
                    entry["configurationNotifications"]
                except KeyError as dummy:
                    continue
                
                for ec in entry["configurationNotifications"]:
                    if ec["ruleId"][:3] != "BA3":
                        # ignore ELF rules
                        try:
                            dbcursor.execute(
                                "INSERT INTO " + "BinSkimFiles" + " VALUES (" + "?," * 7 + "?)",
                                # FileName, SHA256, SHA1, RuleId, Result
                                (basename, hashes[0], hashes[1], ec["ruleId"], ec["id"],
                                # MessageId, Message
                                "", ec["message"]["text"],
                                # time
                                strtime))
                            count = count + 1
                        except sqlite3.Error as error:
                            _bsklogger.log(logging.DEBUG, ("[PBSK] INSERT ConfigurationNotifications error (incomplete): " + error.args[0]))
    except FileNotFoundError as error:
        logmsg = ("[PBSK] {-} Skipping insertion into DB. " + bskjson + " not found.")
        _bsklogger.log(logging.DEBUG, logmsg)

    dbcursor.execute("END TRANSACTION")
    rmfile(bskjson)
    
    _bsklogger.log(logging.DEBUG, ("[PBSK] " + str(count) + 
                " rules were applied on " + file))

    dbcursor.close()
    