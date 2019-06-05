import json

import sqlite3

import os.path

import subprocess

import logging, logging.handlers

import BamLogger

from time import time

from pathlib import Path

from support.utils import getfilehashes

from globs import DIGISIGNTABLE, DBCONN2

_pcertlogger = logging.getLogger("BAM.post_cert")

def pcert_logconfig(queue):
    global _pcertlogger

    qh = logging.handlers.QueueHandler(queue)
    _pcertlogger.addHandler(qh)
    _pcertlogger.setLevel(logging.DEBUG)


def analyzepesignature(file):
    global _pcertlogger
    
    _pcertlogger.log(logging.DEBUG, "[PCERT] Working on " + file + " for certificate information and signature verification")

    pscmdpath = os.environ['systemdrive'] + '\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe'
    args = pscmdpath + ' -nologo -noprofile -executionpolicy bypass -Command ".\\post\\ps_dgsverify.ps1 -binarypath \'' + file + '\'"'

    vfile = Path(pscmdpath)
    if not vfile.exists():
        _pcertlogger.log(logging.DEBUG, "[PCERT] Provided PS path (" + pscmdpath + ") does not exist. Skipping " + file)
        return
    elif not vfile.is_file():
        _pcertlogger.log(logging.DEBUG, "[PCERT] Provided file (" + pscmdpath + ") does not exist. Skipping.....")
        return

    hashes = getfilehashes(file)

    if hashes is None:
        _pcertlogger.log(logging.DEBUG, "[PCERT] Error getting hashes for " + file)
        return        

    _pcertlogger.log(logging.DEBUG, "[PCERT] Starting: " + args)

    try:
        with subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as dgsverify:
            rawout, dummy = dgsverify.communicate()
            pecerts = None
            try:
                pecerts = json.loads(rawout)
            except json.decoder.JSONDecodeError as error:
                _pcertlogger.log(logging.DEBUG, "[PCERT] JSON Error: "  + error.msg)
                return



            try:
                strtime = str(time())
                isosbinary = False
                if pecerts["IsOSBinary"] == "True":
                    isosbinary = True

                dbcursor = DBCONN2.cursor()

                dbcursor.execute("BEGIN TRANSACTION")
                    
                dbcursor.execute(
                    "INSERT INTO " + "DigiSignFiles" + " VALUES (" + "?," * 24 + "?)",
                    # FileName, SHA256, SHA1, Status, StatusMessage
                    (file, hashes[0], hashes[1], pecerts["Status"], pecerts["StatusMessage"],
                    # SignatureType, IsOSBinary, SignerCertificateName
                    int(pecerts["SignatureType"]), int(isosbinary), pecerts["SignerCertificateName"],
                    # SignerCertificateFriendlyName, SignerCertificateIssuer
                    pecerts["SignerCertificateFriendlyName"], pecerts["SignerCertificateIssuer"],
                    # SignerCertificateSerialNumber
                    pecerts["SignerCertificateSerialNumber"],
                    # SignerCertificateNotBefore, SignerCertificateNotAfter
                    pecerts["SignerCertificateNotBefore"], pecerts["SignerCertificateNotAfter"],
                    # SignerCertificateThumbprint, TimeStamperCertificateSubject
                    pecerts["SignerCertificateThumbprint"], pecerts["TimeStamperCertificateSubject"],
                    # TimeStamperCertificateFriendlyName, TimeStamperCertificateIssuer
                    pecerts["TimeStamperCertificateFriendlyName"], pecerts["TimeStamperCertificateIssuer"],
                    # TimeStamperCertificateSerialNumber, TimeStamperCertificateNotBefore
                    pecerts["TimeStamperCertificateSerialNumber"], pecerts["TimeStamperCertificateNotBefore"],
                    # TimeStamperCertificateNotAfter, TimeStamperCertificateThumbprint
                    pecerts["TimeStamperCertificateNotAfter"], pecerts["TimeStamperCertificateThumbprint"],
                    # NumberOfCertsInSignerChain, NumberOfCertsInTimeStampChain
                    int(pecerts["NumberOfCertsInSignerChain"]), int(pecerts["NumberOfCertsInTimeStampChain"]),
                    # PsObjdata, 
                    pecerts["PsObjData"], strtime))
                    
                dbcursor.execute("END TRANSACTION")

                dbcursor.close()
            except sqlite3.Error as error:
                _pcertlogger.log(logging.DEBUG, ("[PCERT] INSERT Certificate/Digital Signature Information error: " + error.args[0]))

    except subprocess.CalledProcessError as error:
        logmsg = ("[PCERT] {-} Skipping insertion into DB. PowerShell commanded failed with error: " + str(error.returncode) + 
                ". Command: " + args)
        _pcertlogger.log(logging.DEBUG, logmsg)
    except FileNotFoundError as error:
        logmsg = ("[PBSK] {-} Skipping insertion into DB. powershell.exe not found")
        _pcertlogger.log(logging.DEBUG, logmsg)

    _pcertlogger.log(logging.DEBUG, "[PCERT] " + file + " Completed")
