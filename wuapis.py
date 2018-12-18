
import sqlite3

import logging, logging.handlers

import globs

import BamLogger

from db.bam_analysis_db import prodvgtebyname

from support.utils import verifyhex

_wdblogger = logging.getLogger("BAM.wuapis")

def db_logconfig(queue):
    global _wdblogger

    qh = logging.handlers.QueueHandler(queue)
    _wdblogger.addHandler(qh)
    _wdblogger.setLevel(logging.DEBUG)

def getsupersededfromfiledigest(filedigest):
    '''
    Lists all superseded updates
    '''
    global _wdblogger

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersededfromfile")
        return hexfiledigest

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision as ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevisionSupersedesUpdate rsu ON rsu.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.UpdateID = rsu.SupersededUpdateID '
            'WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getsupersededfromfile")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getsupersededfromfile")
    wsuscursor.close()
    return result

def getsupersededfromfiledigest_custom(filedigest):
    '''
    File to superseded updates; Determines if Digest is superseding (list all superseded updates for file if any)
    '''

    global _wdblogger

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersededfromfile")
        return hexfiledigest

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
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getsupersededfromfile")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getsupersededfromfile")
    wsuscursor.close()
    return result

def getsupersedingfromfile(filedigest):
    global _wdblogger

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getsupersedingfromfile")
        return hexfiledigest

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
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from prodvgtebyname")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from prodvgtebyname")
    wsuscursor.close()
    return result

def getfiledigestattributes(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB) with other WSUS information
    '''
    global _wdblogger

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getfiledigestattributes")
        return hexfiledigest

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision AS ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON tbd.BundledRevisionID = ffr.RevisionID '
            'JOIN SUSDB.dbo.tbRevision r ON r.RevisionID = tbd.RevisionID '
            'JOIN SUSDB.dbo.tbUpdate u ON u.LocalUpdateID = r.LocalUpdateID '
            'JOIN SUSDB.PUBLIC_VIEWS.vUpdate vu ON vu.UpdateId = u.UpdateID '
                ' WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getfiledigestattributes")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getfiledigestattributes")
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

                if result is None:
                    continue

                hexfiledigest = verifyhex("0x" + row[column])

                if hexfiledigest is None:
                    _wdblogger.log(logging.DEBUG, 
                            "[WUAPIS] {} not valid hex: getfileattrbyfnprodv".format(row[column]))
                    continue

                hashlist.append(hexfiledigest)

    fileattrlist = []

    for hash in hashlist:
        r = getfiledigestattributes(hash)
        if r is None:
            continue
        fileattrlist.append(r)

    bamcursor.close()
    wsuscursor.close()
    return fileattrlist

def findupdate(updateid):
    global _wdblogger

    if not isinstance(updateid, str):
        return None

    wsuscursor = globs.DBWSUSCONN.cursor()

    bamcursor = globs.DBCONN.cursor()
    utbname = globs.UPDATEFILESDBNAME
    check = bamcursor.execute("SELECT FileName FROM {} WHERE FileName = '{}'".format(utbname, updateid))
    
    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findupdate")
        bamcursor.close()
        wsuscursor.close()
        return check

    result = bamcursor.fetchall()
    bamcursor.close()
    wsuscursor.close()

    return result

def getKBoffiledigest(filedigest):
    '''
    Digest (cab/exe) to KB (file to KB)
    '''
    global _wdblogger

    hexfiledigest = verifyhex(filedigest)

    if hexfiledigest is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid hex: getKBoffiledigest")
        return hexfiledigest

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT * FROM SUSDB.dbo.tbFileForRevision  as ffr '
            'JOIN SUSDB.dbo.tbBundleDependency tbd ON ffr.RevisionID = tbd.BundledRevisionID '
            'JOIN SUSDB.dbo.tbKBArticleForRevision kbfr ON kbfr.RevisionID = tbd.RevisionID '
                'WHERE ffr.FileDigest = {}').format(hexfiledigest)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getKBoffiledigest")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getKBoffiledigest")
    wsuscursor.close()
    return result    

def getKBtofiledigest(kbarticle):
    '''
    KB to file(s)
    '''
    global _wdblogger
    
    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: getKBtofiledigest")
        return None

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ('SET NOCOUNT ON;SELECT f.FileDigest, f.FileName, kbafr.KBArticleID '
                'FROM SUSDB.dbo.tbKBArticleForRevision kbafr '
            'JOIN SUSDB.dbo.tbBundleDependency bd ON kbafr.RevisionID = bd.RevisionID '
            'JOIN SUSDB.dbo.tbFileForRevision ffr ON ffr.RevisionID = bd.BundledRevisionID '
            'JOIN SUSDB.dbo.tbFile f ON f.FileDigest = ffr.FileDigest '
            'WHERE kbafr.KBArticleID = {} ORDER BY FileDigest').format(str(kbarticle))

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from getKBtofiledigest")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from getKBtofiledigest")
    wsuscursor.close()
    return result

def findfileswithkb(kbarticle):
    '''
    find files that have a filename with KB number in it. May not guarantee to capture all related files.
    '''
    global _wdblogger
    
    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: findfileswithkb")
        return None

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ("SET NOCOUNT ON;SELECT FileName, FileDigest FROM SUSDB.dbo.tbFile "
            "WHERE FileName collate SQL_Latin1_General_CP1_CI_AS LIKE '%{}%'").format(str(kbarticle))

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findfileswithkb")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from findfileswithkb")
    wsuscursor.close()
    return result

def findupdateinfo(updateid):
    global _wdblogger

    if not isinstance(updateid, str):
        return None

    wsuscursor = globs.DBWSUSCONN.cursor()

    tsql = ("SET NOCOUNT ON;SELECT * FROM SUSDB.PUBLIC_VIEWS.vUpdate "
    "WHERE UpdateId = CAST('{}' as uniqueidentifier)").format(updateid)

    check = wsuscursor.execute(tsql)

    if check is None:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] Did not find entries from findupdateinfo")
        wsuscursor.close()
        return check

    result = wsuscursor.fetchall()

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from findupdateinfo")
    wsuscursor.close()
    return result

def kbtosupersedingkb(kbarticle):
    global _wdblogger

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: kbtosupersedingkb")
        return None

    updateinfo = []
    fdlist = getKBtofiledigest(kbarticle)

    if fdlist is None:
        return None

    for filed in fdlist:
        superfiles = getsupersedingfromfile(filed[0])

        if superfiles is None:
            return None

        for superfile in superfiles:
            uinfo = findupdateinfo(superfile[1])

            if uinfo is None:
                return None

            updateinfo.append(uinfo[0][13])
        
    kbsorted = None

    if len(updateinfo) != 0:
        kbsorted = list(sorted(set(updateinfo)))  

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from kbtosupersedingkb")
    return kbsorted

def kbtosupersededkb(kbarticle):
    global _wdblogger

    try:
        kbarticleint = int(kbarticle)
    except ValueError:
        _wdblogger.log(logging.DEBUG, "[WUAPIS] argument not valid int: kbtosupersedingkb")
        return None

    updateinfo = []
    fdlist = getKBtofiledigest(kbarticle)

    if fdlist is None:
        return None

    for filed in fdlist:
        superfiles = getsupersededfromfiledigest(filed[0])

        if superfiles is None:
            continue
            
        for superfile in superfiles:
            uinfo = findupdateinfo(superfile[6])
            
            if uinfo is None:
                continue

            updateinfo.append(uinfo[0][13])

    kbsorted = None

    if len(updateinfo) != 0:
        kbsorted = list(sorted(set(updateinfo)))     

    _wdblogger.log(logging.DEBUG, "[WUAPIS] Found entries from kbtosupersedingkb")
    return kbsorted    