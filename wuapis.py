
import sqlite3

import logging, logging.handlers

import globs

import BamLogger

from db.bam_analysis_db import prodvgtebyname

from support.utils import verifyhex

_wulogger = logging.getLogger("BAM.wuapis")

def db_logconfig(queue):
    global _wulogger

    qh = logging.handlers.QueueHandler(queue)
    _wulogger.addHandler(qh)
    _wulogger.setLevel(logging.DEBUG)

def getsupersededfromfiledigest(filedigest):
    '''
    Lists all superseded updates
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersededfromfile")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision as ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevisionSupersedesUpdate rsu ON rsu.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.UpdateID = rsu.SupersededUpdateID '
            'WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getsupersededfromfile")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getsupersededfromfile (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getsupersededfromfiledigest_custom(filedigest):
    '''
    File to superseded updates; Determines if Digest is superseding (list all superseded updates for file if any)
    '''

    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersededfromfile")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;'
            'DECLARE @supersededupdates table '
            '(FileDigest varbinary(max), RevisionID INT, FileName varchar(max), '
                'LegacyName varchar(max), SupersededUpdateID uniqueidentifier);'
            'INSERT INTO @supersededupdates (FileDigest, RevisionID, FileName, LegacyName, SupersededUpdateID) '
            'SELECT ffr.FileDigest, ffr.RevisionID, f.FileName, u.LegacyName, rsu.SupersededUpdateID '
                'FROM SUSDB.dbo.tbFileForRevision as ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevisionSupersedesUpdate rsu ON rsu.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.UpdateID = rsu.SupersededUpdateID '
            'JOIN SUSDB.dbo.tbFile f ON f.FileDigest = ffr.FileDigest '
                'WHERE ffr.FileDigest = {};'
            'SELECT * FROM @supersededupdates').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getsupersededfromfile")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getsupersededfromfile (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getsupersedingfromfile(filedigest):
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersedingfromfile")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = (''
    'SET NOCOUNT ON;DECLARE @supersedingupdates table (FileDigest varbinary(max), RevisionID INT, '
        'LegacyName varchar(max), SuperRevisionID int);'
    'INSERT INTO @supersedingupdates (FileDigest, RevisionID, LegacyName, SuperRevisionID) '
    '   SELECT ffr.FileDigest, ffr.RevisionID, u.LegacyName, rsu.RevisionID FROM SUSDB.dbo.tbFileForRevision as ffr'
    '   JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID'
    '   JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = tbd.RevisionID'
    '   JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID'
    '   JOIN SUSDB.dbo.tbRevisionSupersedesUpdate rsu ON rsu.SupersededUpdateID = u.UpdateID'
    '   WHERE ffr.FileDigest = {};'
    'SELECT * FROM tbUpdate WHERE LocalUpdateID IN (SELECT LocalUpdateID FROM tbRevision'
    '   WHERE RevisionID IN (SELECT SuperRevisionID FROM @supersedingupdates));').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getsupersedingfromfile")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getsupersedingfromfile (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getfiledigestbattributeswodu(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB) with other WSUS information (Bundled)
    without DefinitionUpdates
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getfiledigestbattributeswodu")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision AS ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID '
            'JOIN SUSDB.PUBLIC_VIEWS.vUpdate vu ON vu.UpdateId = u.UpdateID '
            "WHERE ffr.FileDigest = {} AND ClassificationId != 'E0789628-CE08-4437-BE74-2495B842F43B'").format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getfiledigestbattributeswodu")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getfiledigestbattributeswodu (" + str(filedigest) + ")")
    wsuscursor.close()
    return result


def getfiledigestbattributes(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB) with other WSUS information (Bundled)
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getfiledigestbattributes")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision AS ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID '
            'JOIN SUSDB.PUBLIC_VIEWS.vUpdate vu ON vu.UpdateId = u.UpdateID '
                ' WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getfiledigestbattributes")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getfiledigestbattributes (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getfiledigestattributeswodu(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB) with other WSUS information
    without DefinitionUpdates.
    May return multiple results.
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getfiledigestattributeswodu")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision AS ffr'
            ' JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = ffr.RevisionID'
            ' JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID'
            ' JOIN SUSDB.PUBLIC_VIEWS.vUpdate vu ON vu.UpdateId = u.UpdateID'
            " WHERE ffr.FileDigest = {} AND ClassificationId != 'E0789628-CE08-4437-BE74-2495B842F43B'").format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getfiledigestattributeswodu")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getfiledigestattributeswodu (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getfiledigestattributes(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB) with other WSUS information.
    May return multiple results.
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getfiledigestattributes")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision AS ffr'
            ' JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = ffr.RevisionID'
            ' JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID'
            ' JOIN SUSDB.PUBLIC_VIEWS.vUpdate vu ON vu.UpdateId = u.UpdateID'
            ' WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getfiledigestattributes")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getfiledigestattributes (" + str(filedigest) + ")")
    wsuscursor.close()
    return result

def getfileattrbyfnprodv(filename, prodversion):
    bamcursor = globs.DBCONN.cursor()
    wsuscursor = globs.DBWSUSCONN.cursor()
    filelist = prodvgtebyname(bamcursor, filename, prodversion)

    hashlist = []

    for row in filelist:
        for column in row.keys():
            if column == 'UpdateId':
                result = findupdate(row[column])

                if len(result) == 0:
                    continue

                hexfiledigest = verifyhex("0x" + row[column])

                if hexfiledigest is None:
                    _wulogger.log(logging.DEBUG, 
                            "[WUAPIS] {} not valid hex: getfileattrbyfnprodv".format(row[column]))
                    continue

                hashlist.append(hexfiledigest)

    fileattrlist = []

    for hash in hashlist:
        r = getfiledigestbattributes(hash)
        if len(r) == 0:
            continue
        fileattrlist.append(r)

    bamcursor.close()
    wsuscursor.close()
    return fileattrlist

def findupdate(updateid):
    global _wulogger

    result = []

    if not isinstance(updateid, str):
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    bamcursor = globs.DBCONN.cursor()
    utbname = globs.UPDATEFILESDBNAME
    check = bamcursor.execute("SELECT FileName FROM {} WHERE FileName = '{}'".format(utbname, updateid))
    
    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findupdate")
        bamcursor.close()
        wsuscursor.close()
        return result

    result = bamcursor.fetchall()
    bamcursor.close()
    wsuscursor.close()

    return result

def getKBoffiledigest(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB)
    '''
    global _wulogger

    result = []

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getKBoffiledigest")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision  as ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON ffr.RevisionID = tbd.BundledRevisionID '
            'JOIN SUSDB.dbo.tbKBArticleForRevision kbfr ON kbfr.RevisionID = tbd.RevisionID '
                'WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getKBoffiledigest")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getKBoffiledigest (" + str(filedigest) + ")")
    wsuscursor.close()
    return result    

def getKBtofiledigest(kbarticle):
    '''
    KB to file(s) without matching platform
    '''
    global _wulogger
    
    result = []

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: getKBtofiledigest")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT f.FileDigest, f.FileName, kbafr.KBArticleID '
                'FROM SUSDB.dbo.tbKBArticleForRevision kbafr '
            'JOIN SUSDB.dbo.tbBundleDependency bd ON kbafr.RevisionID = bd.RevisionID '
            'JOIN SUSDB.dbo.tbFileForRevision ffr ON ffr.RevisionID = bd.BundledRevisionID '
            'JOIN SUSDB.dbo.tbFile f ON f.FileDigest = ffr.FileDigest '
            'WHERE kbafr.KBArticleID = {} ORDER BY FileDigest').format(str(kbarticle))

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getKBtofiledigest")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getKBtofiledigest (" + str(kbarticle) + ")")
    wsuscursor.close()
    return result

def getKBtoufiledigest(kbarticle, filedigest):
    '''
    KB to filedigest with matching platform
    '''
    global _wulogger
    
    result = []

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: getKBtofiledigest")
        return result

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getKBoffiledigest")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT f.FileDigest, f.FileName, kbafr.KBArticleID '
                'FROM SUSDB.dbo.tbKBArticleForRevision kbafr '
            'JOIN SUSDB.dbo.tbBundleDependency bd ON kbafr.RevisionID = bd.RevisionID '
            'JOIN SUSDB.dbo.tbFileForRevision ffr ON ffr.RevisionID = bd.BundledRevisionID '
            'JOIN SUSDB.dbo.tbFile f ON f.FileDigest = ffr.FileDigest '
            'WHERE kbafr.KBArticleID = {} AND ffr.FileDigest =  {} '
            '').format(str(kbarticle), hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getKBtofiledigest")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from getKBtofiledigest (" + str(kbarticle) + ")")
    wsuscursor.close()
    return result

def findfileswithkb(kbarticle):
    '''
    find files that have a filename with KB number in it. May not guarantee to capture all related files.
    '''
    global _wulogger
    
    result = []

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: findfileswithkb")
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ("SET NOCOUNT ON;SELECT FileName, FileDigest FROM SUSDB.dbo.tbFile "
            "WHERE FileName collate SQL_Latin1_General_CP1_CI_AS LIKE '%{}%'").format(str(kbarticle))

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findfileswithkb")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from findfileswithkb (" + str(kbarticle) + ")")
    wsuscursor.close()
    return result

def findupdateinfo(updateid):
    global _wulogger

    result = []

    if not isinstance(updateid, str):
        return result

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ("SET NOCOUNT ON;SELECT * FROM SUSDB.PUBLIC_VIEWS.vUpdate "
    "WHERE UpdateId = CAST('{}' as uniqueidentifier)").format(updateid)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findupdateinfo")
        wsuscursor.close()
        return result

    result = wsuscursor.fetchall()

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from findupdateinfo" + "(" + str(updateid) +")")
    wsuscursor.close()
    return result

def kbtosupersedingkb(kbarticle, filedigest):
    global _wulogger

    result = []

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: kbtosupersedingkb" + "(" + str(kbarticle) + ")")
        return result

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: kbtosupersedingkb")
        return result

    updateinfo = []
    fdlist = getKBtoufiledigest(kbarticle, hexfiledigest)

    if len(fdlist) == 0:
        return result

    for filed in fdlist:
        superfiles = getsupersedingfromfile(filed[0])

        if len(superfiles) == 0:
            continue

        for superfile in superfiles:
            uinfo = findupdateinfo(superfile[1])

            if len(uinfo) == 0:
                continue

            if uinfo[0][13] is not None:
                updateinfo.append(uinfo[0][13])
        
    kbsorted = []

    if len(updateinfo) != 0:
        kbsorted = list(sorted(set(updateinfo)))  

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from kbtosupersedingkb (" + str(kbarticle) + ")")
    return kbsorted

def kbtosupersededkb(kbarticle, filedigest):
    global _wulogger

    result = []

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: kbtosupersededkb")
        return result

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wulogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: kbtosupersededkb")
        return result

    updateinfo = []
    fdlist = getKBtoufiledigest(kbarticle, hexfiledigest)

    if len(fdlist) == 0:
        return result

    for filed in fdlist:
        superfiles = getsupersededfromfiledigest(filed[0])

        if len(superfiles) == 0:
            continue
            
        for superfile in superfiles:
            uinfo = findupdateinfo(superfile[6])
            
            if len(uinfo) == 0:
                continue

            if uinfo[0][13] is not None:
                updateinfo.append(uinfo[0][13])

    kbsorted = []

    if len(updateinfo) != 0:
        kbsorted = list(sorted(set(updateinfo)))     

    _wulogger.log(logging.DEBUG, "[WUAPIS] Found entries from kbtosupersededkb (" + str(kbarticle) + ")")
    return kbsorted

def updatewuentrysecedenceinfo():
    bamcursor = globs.DBCONN.cursor()
    bamcursor.execute("SELECT SHA1 FROM " + globs.UPDATEFILESDBNAME + " WHERE Seceding = '' OR SecededBy = ''")
    result = bamcursor.fetchall()
    count = 0

    bamcursor.execute("BEGIN TRANSACTION")
    for row in result:
        for column in row.keys():
            if str(row[column]) != 'None':
        
                fattrs = getfiledigestbattributeswodu(row[column])
                kbarticle = None
                if len(fattrs) == 0: # Update is not part of a bundle
                    fattrs = getfiledigestattributeswodu(row[column])

                    if len(fattrs) == 0:
                        _wulogger.log(logging.DEBUG, "[WUAPIS] Possibly a DefinitionUpdate. Skipping...")
                        continue
                    
                    kbarticle = fattrs[0][42]
                else:
                    kbarticle = fattrs[0][44]
                
                # check if file has an assoicated KB number
                if kbarticle is not None:
                    superseding = kbtosupersedingkb(kbarticle, row[column])
                    superseded = kbtosupersededkb(kbarticle, row[column])
                    secededlist = ""
                    secedinglist = ""

                    if len(superseding) == 0 and len(superseded) == 0:
                        pass
                    elif len(superseding) == 0:
                        secededlist = ','.join(superseded)
                        bamcursor.execute(("UPDATE UpdateFiles" 
                                        " SET Seceding = " 
                                        "'{}' WHERE SHA1 = '{}'").format(secededlist, row[column]))
                    elif len(superseded) == 0:
                        secedinglist = ",".join(superseding)
                        bamcursor.execute(("UPDATE UpdateFiles" 
                                        " SET SecededBy = " 
                                        "'{}' WHERE SHA1 = '{}'").format(secedinglist, row[column]))
                    else:
                        bamcursor.execute(("UPDATE UpdateFiles" 
                                        " SET Seceding = " 
                                        "'{}' WHERE SHA1 = '{}'").format(secededlist, row[column]))
                        bamcursor.execute(("UPDATE UpdateFiles" 
                                        " SET SecededBy = " 
                                        "'{}' WHERE SHA1 = '{}'").format(secedinglist, row[column]))
                    count = count + 1
                    if count % 5000 == 0:
                        bamcursor.execute("END TRANSACTION")
                        bamcursor.execute("BEGIN TRANSACTION")
                else:
                    _wulogger.log(logging.DEBUG, "[WUAPIS]  Skipping no KB...")

    bamcursor.execute("END TRANSACTION")
    bamcursor.close()
    return result
