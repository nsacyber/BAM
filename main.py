#! python3
'''
main method along with argument parsing functions
'''
# ************************************************************
# Imports
# ************************************************************
import sys

# Verify Python version
if sys.version_info[0] <= 3 and sys.version_info[1] < 7:
    sys.exit("This script requires at least Python version 3.7.")

import argparse

from pathlib import Path

import os

import logging

import multiprocessing as mp

from support.utils import exitfunction, util_logconfig

from db.wsuse_db import construct_tables, construct_post_tables, db_logconfig

from ProcessPools import DBMgr, CabMgr, PSFXMgr, PEMgr, SymMgr, mgr_logconfig

from post.post_binskim import binskim_logconfig

from post.post_cert import pcert_logconfig

from post.post_banned import pbanned_logconfig

import globs

import BamLogger

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
        "-a", "--allanalysis",
        action='store_true',
        help="Perform all post-analysis. Requires -pa.")
    parser.add_argument(
        "-bsk", "--binskim",
        action='store_true',
        help="Perform BinSkim post-analysis. Requires -pa.")
    parser.add_argument(
        "-c", "--createdbonly", action='store_true')
    parser.add_argument(
        "-gp", "--getpatches",
        help="Create/Update patches DB information for symbol files " +
        "(requires --createdbonly and cannot be used with any other \"get\" option)",
        action='store_true')
    parser.add_argument(
        "-gs", "--getsymbols",
        help="Create/Update symbol DB information for extracted PE files " +
        "(requires --createdbonly and cannot be used with any other \"get\" option)",
        action='store_true')
    parser.add_argument(
        "-gu", "--getupdates",
        help="Create/Update update file DB information for update files " +
        "(requires --createdbonly and cannot be used with any other \"get\" option)",
        action='store_true')
    parser.add_argument(
        "-f", "--file", help="Path to single patch file. Must be given -x or --extract as well.")
    parser.add_argument(
        "-m", "--module",
        help="specify module to invoke",
        nargs="?",
        type=str,
        default="updatefilesymbols")
    parser.add_argument(
        "-p", "--patchpath", help="Path to location where Windows updates " +
        "(CAB/MSU) are stored. Must be given -x or --extract as well.")
    parser.add_argument(
        "-pa", "--postanalysis",
        action='store_true',
        help="Perform post-analysis")
    parser.add_argument(
        "-pd", "--patchdest",
        help="An optional destination where extracted PE files will be stored",
        nargs="?",
        type=str,
        default="extractedPatches")
    parser.add_argument(
        "-pb", "--basepatchdir",
        help="The directory where the base versions of files for hydration are stored",
        type=str,
        default="C:\\Windows\\System32"
    )
    parser.add_argument(
        "-raf", "--reanalyzeaf",
        action='store_true',
        help="Reanalyze all files. Requires -pa.")
    parser.add_argument(
        "-rsf", "--reanalyzesf",
        action='store_true',
        help="Reanalyze single file. Requires -pa.")
    parser.add_argument(
        "-s", "--singleanalysis",
        nargs="?",
        type=str,
        help="Perform post-analysis on single file. Requires -pa.")
    parser.add_argument(
        "-sd", "--singlediranalysis",
        nargs="?",
        type=str,
        help="Perform post-analysis on all files within a directory." + 
        "single file. Requires -pa.")
    parser.add_argument(
        "-sl", "--symlocal",
        help=("Path to location where local symbols are be stored. "
              "Used only to populate the database and move symbols to "
              "specified location."),
        action='store_true')
    parser.add_argument(
        "-ss", "--symbolserver",
        help="UNC Path to desired Symbol server. Defaults to "
        "https://msdl.microsoft.com/download/symbols. If symlocal is"
        " specified a local directory is used",
        nargs="?",
        type=str,
        default="https://msdl.microsoft.com/download/symbols"
        )
    parser.add_argument(
        "-sp", "--symdestpath",
        help="Path to location where obtained symbols will be stored",
        nargs="?",
        type=str,
        default="updatefilesymbols")
    parser.add_argument(
        "-x", "--extract", action='store_true')
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        help="turn verbose output on or off"
    )

    if len(sys.argv) == 1:
        displayhelp(parser)
        exitfunction()

    return parser.parse_args()


def checkdirectoryexist(direxist):
    '''
    Check if directory exists
    '''
    result = True
    if not os.path.isdir(("%r"%direxist)[1:-1]):
        try:
            os.mkdir(direxist)
        except FileExistsError as ferror:
            mainlogger.log(logging.ERROR, "[MAIN] {-} unable to make destination directory - FileExists " + \
                    str(ferror.winerror) + " " +  str(ferror.strerror))
        except:
            exctype, value = sys.exc_info()[:2]
            mainlogger.log(logging.ERROR, ("[MAIN] {-} unable to make destination directory " + \
                    str(exctype) + " " + str(value)))
            result = False
    mainlogger.log(logging.INFO, "[MAIN] Directory ("+ direxist + ") results were " + str(int(result)))
    return result

def setuplogconfig(globqueue):
    util_logconfig(globqueue)
    db_logconfig(globqueue)
    mgr_logconfig(globqueue)
    binskim_logconfig(globqueue)
    pcert_logconfig(globqueue)
    pbanned_logconfig(globqueue)

def closeup():
    globs.DBCONN.close()
    globs.DBCONN2.close()
    globqueue.put_nowait(None)
    loggerProcess.join()
    sys.exit()

if __name__ == "__main__":

    import time

    PARSER = argparse.ArgumentParser()
    ARGS = parsecommandline(PARSER)

    # ************************************************************
    # times
    # ************************************************************
    ELPASED_EXTRACT = 0
    ELPASED_CHECKBIN = 0
    ELPASED_GETSYM = 0
    START_TIME = 0
    EXTRACTMIN = 0
    CHECKBINMIN = 0
    GETSYMMIN = 0

    # set verbose output on or off, this is apparently the Python approved way to do this
    globqueue = mp.Manager().Queue(-1)
    mainlogger = logging.getLogger("BAM.main")
    qh = logging.handlers.QueueHandler(globqueue)
    qh.setLevel(logging.INFO)
    mainlogger.addHandler(qh)
    mainlogger.setLevel(logging.INFO)

    setuplogconfig(globqueue)

    loggerProcess = mp.Process(target=BamLogger.log_listener, args=(globqueue, BamLogger.log_config))
    loggerProcess.start()
    
    if ARGS.verbose:
        import ModVerbosity

    # ARGS.file currently not in use, way to extract single cab not yet developed
    if ARGS.extract and (ARGS.patchpath or ARGS.file):
        # Clean-slate (first time) / Continuous use or reconstruct DB
        # (internet or no internet)
        print("Extracting updates and retrieving symbols")

        patchdest = None

        direxist = False

        if ARGS.patchdest:
            direxist = checkdirectoryexist(ARGS.patchdest)
        
        if not direxist:
            mainlogger.log(logging.ERROR, "[MAIN] {-} Problem verifying patch destination directory")
            closeup()

        patchdest = ARGS.patchdest.rstrip('\\')
        if ARGS.patchpath:
            patchpath = ARGS.patchpath
            print("Examining " + ARGS.patchpath)

            patchpathiter = ""
            try:
                patchpathiter = os.scandir(ARGS.patchpath)
            except FileNotFoundError as error:
                mainlogger.log(logging.ERROR, "[MAIN] {-} Problem verifying patch directory. Not found.")
                closeup()

            if not any(patchpathiter):
                mainlogger.log(logging.ERROR, "[MAIN] {-} Provided patch directory is empty.")
                closeup()
        elif ARGS.file:
            patchpath = ARGS.file

        if ARGS.symdestpath:
            direxist = checkdirectoryexist(ARGS.symdestpath)

        if not direxist:
            mainlogger.log(logging.ERROR, "[MAIN] {-} Problem verifying symbol destination directory")
            closeup()

        if not construct_tables(globs.DBCONN):
            mainlogger.log(logging.ERROR, "[MAIN] {-} Problem creating DB tables")
            closeup()

        DB = DBMgr(patchdest, globs.DBCONN)
        SYM = PATCH = UPDATE = None

        LOCAL = False
        LOCALDBC = False

        if ARGS.symlocal:
            print("Using local path for symbols....")
            LOCAL = True

        if ARGS.createdbonly:
            print("Creating local DB only....")
            LOCALDBC = True

        print("Using symbol server (" + ARGS.symbolserver + ") to store at (" + \
              ARGS.symdestpath + ")")

        # number of processes spawned will be equal to the number of CPUs in the system
        CPUS = os.cpu_count()

        SYM = SymMgr(CPUS, ARGS.symbolserver, ARGS.symdestpath, DB, LOCAL, globqueue)
        PATCH = PEMgr(CPUS, SYM, DB, globqueue)
        PSFX = PSFXMgr(patchpath, patchdest, CPUS, PATCH, DB, LOCALDBC, globqueue, ARGS.basepatchdir)
        UPDATE = CabMgr(patchpath, patchdest, CPUS, PATCH, PSFX, DB, LOCALDBC, globqueue)

        START_TIME = time.time()
        DB.start()
        SYM.start()
        PATCH.start()
        PSFX.start()
        UPDATE.start()

        UPDATE.join()
        ELPASED_EXTRACT = time.time() - START_TIME
        EXTRACTMIN = ELPASED_EXTRACT / 60
        print(("Time to extract ({}),").format(EXTRACTMIN))
        PATCH.join()
        ELPASED_CHECKBIN = time.time() - START_TIME
        CHECKBINMIN = ELPASED_CHECKBIN / 60
        print(("Time to check binaries ({}),").format(CHECKBINMIN))
        SYM.join()
        ELAPSED_GETSYM = time.time() - START_TIME
        GETSYMMIN = ELAPSED_GETSYM / 60
        print(("Time to find symbols ({}),").format(GETSYMMIN))
        DB.join()
        TOTAL_ELAPSED = time.time() - START_TIME
        TOTALMIN = TOTAL_ELAPSED / 60
        print(("Total time including database insertion ({})").format(TOTALMIN))

        print("Updates Completed, check WSUS_Update_data.db for symbols, "
              "update metadata, binaries")
    elif ARGS.createdbonly and ARGS.patchpath and ARGS.symbolserver and ARGS.patchdest:
        # Create/Update DB only from Update files, extracted files,
        # and downloaded symbols

        # Only create the SymbolFiles Table
        if ARGS.getsymbols:
            if not construct_tables(globs.DBCONN):
                mainlogger.log(logging.ERROR, "[MAIN] {-} Problem creating DB tables")
                closeup()

            # (Re)create the Symbol table / retrieve symbols only
            DB = DBMgr(globs.DBCONN)
            SYM = None

            print("Only retrieving symbols")
            LOCAL = False
            if ARGS.symlocal:
                LOCAL = True

            SYM = SymMgr(4, ARGS.symbolserver, ARGS.symdestpath, DB, LOCAL, globqueue)

            DB.start()
            SYM.start()

            for root, dummy, files in os.walk(ARGS.patchdest):
                for item in files:
                    job = Path(os.path.join(root + "\\" + item)).resolve()
                    SYM.receivejobset(job)

            SYM.donesig()
            SYM.join()

            for i in range(0, 2):
                DB.donesig()
            DB.join()

            print("retrieving of symbols complete. Check WSUS_Update_data.db for symbols")
        # Only create the PatchedFiles Table
        elif ARGS.getpatches:
            if not construct_tables(globs.DBCONN):
                mainlogger.log(logging.ERROR, "[MAIN] {-} Problem creating DB tables")
                closeup()

            # (Re)create the PatchFile table / retrieve patches only
            DB = DBMgr(globs.DBCONN)
            CLEAN = None

            print("Only retrieving patches")

            CLEAN = PEMgr(1, None, DB, globqueue)

            DB.start()
            CLEAN.start()

            for root, folders, dummy in os.walk(ARGS.patchpath):
                for item in folders:
                    job = Path(os.path.join(root + "\\" + item)).resolve()
                    CLEAN.receivejobset(job)

            CLEAN.donesig()
            CLEAN.join()

            for i in range(0, 2):
                DB.donesig()
            DB.join()

            print("retrieving of patches complete. Check WSUS_Update_data.db for patch files")
        # Only create the UpdateFiles Table
        elif ARGS.getupdates:
            if not construct_tables(globs.DBCONN):
                mainlogger.log(logging.ERROR, "[MAIN] {-} Problem creating DB tables")
                closeup()

            # (Re)create the UpdateFiles table / retrieve updates only
            DB = DBMgr(globs.DBCONN)
            UPD = None

            print("Only retrieving updates")

            UPD = CabMgr(ARGS.patchpath, ARGS.patchdest, 4, None, None, DB, True, globqueue)
            DB.start()
            UPD.start()
            UPD.join()

            for i in range(0, 2):
                DB.donesig()
            DB.join()

            print("retrieving of Updates complete. Check WSUS_Update_data.db for update files")
    elif ARGS.postanalysis and ARGS.symbolserver and (ARGS.singleanalysis or ARGS.singlediranalysis):
        from post.post_binskim import binskimanalysis
        from post.post_cert import analyzepesignature
        from post.post_banned import findbannedapis

        fileorpatch = ''

        if ARGS.singleanalysis:
            fileordir = ARGS.singleanalysis
        elif ARGS.singlediranalysis:
            fileordir = []

            for root, dummy, files, in os.walk(ARGS.singlediranalysis):
                for file in files:
                    filel = file.lower()
                    if filel.endswith(".exe") or filel.endswith(".sys") \
                        or filel.endswith(".dll"):
                        fileordir.append(os.path.realpath(os.path.join(root,filel)))

        cresult = construct_post_tables() 

        if cresult:
            print("Starting postanalysis.")
            if ARGS.allanalysis:
                if isinstance(fileordir, list):
                    for file in fileordir:
                        binskimanalysis(file, ARGS.symbolserver)
                        analyzepesignature(file)
                        findbannedapis(file)
                else:
                    binskimanalysis(fileordir, ARGS.symbolserver)
                    analyzepesignature(fileordir)
            
            if ARGS.binskim:
                dummy = ""
            print("Completed postanalysis.")
        else:
            print("Issue constructing post tables.")            

    else:
        print("Invalid option -- view -h")

    print(("Time to extract ({})," +
           "Time to checkbin ({})," +
           "Time to get symbols ({})").format(EXTRACTMIN, CHECKBINMIN,
                                              GETSYMMIN))

    closeup()
