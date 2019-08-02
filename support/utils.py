'''
This module contains various utilitarian functions used by other modules.
'''
#***************************************
# Imports
#***************************************
import sys

import os

import stat

import threading

import logging, logging.handlers

from dependencies.pefile import pefile

import globs

import BamLogger

#*****************************************
# Local variables
#*****************************************
PEARCH = {
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: 'I386',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_R3000']: 'R3000',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_R4000']: 'R4000',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_R10000']: 'R10000',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_WCEMIPSV2']: 'WCEMIPSV2',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ALPHA']: 'ALPHA',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_SH3']: 'SH3',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_SH3DSP']: 'SH3DSP',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_SH3E']: 'SH3E',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_SH4']: 'SH4',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_SH5']: 'SH5',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM']: 'ARM',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_THUMB']: 'THUMB',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARMNT']: 'ARMNT',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AM33']: 'AM33',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_POWERPC']: 'POWERPC',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_POWERPCFP']: 'POWERPCFP',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']: 'IA64',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_MIPS16']: 'MIPS16',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ALPHA64']: 'ALPHA64_AXP64',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AXP64']: 'ALPHA64_AXP64',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_MIPSFPU']: 'MIPSFPU',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_MIPSFPU16']: 'MIPSFPU16',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_TRICORE']: 'TRICORE',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_CEF']: 'CEF',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_EBC']: 'EBC',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']: 'AMD64',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_M32R']: 'M32R',
    pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_CEE']: 'CEE'
}

_utilLogger = logging.getLogger("BAM.util")

def util_logconfig(queue):
    global _utilLogger

    qh = logging.handlers.QueueHandler(queue)
    _utilLogger.addHandler(qh)
    _utilLogger.setLevel(logging.DEBUG)

#***********************************************
# Functions
#***********************************************


def exitfunction():
    '''
    exit process
    '''
    sys.exit(0)

def rmfile(file):
    '''
    Remove file and handle RO conditions
    '''
    if((os.stat(file).st_file_attributes & 0x0000000F) ==
       stat.FILE_ATTRIBUTE_READONLY):
        os.chmod(file, stat.FILE_ATTRIBUTE_NORMAL)
    
    import contextlib

    with contextlib.suppress(FileNotFoundError):
        os.remove(file)

def writeperm(pathtodir):
    '''
    due to python creating directory without write permissions, this function
    is used to allow write permissions so that files and folders can be deleted
    later.
    '''
    global _utilLogger
    for root, dirs, files in os.walk(pathtodir, topdown=True):
        for item in files:
            try:
                os.chmod(os.path.join(root, item), stat.S_IWRITE)
            except FileNotFoundError as dummy:
                _utilLogger.log(logging.DEBUG, "writeperm: cannot find " + str(item))
                pass
        for folder in dirs:
            try:
                os.chmod(os.path.join(root, folder), stat.S_IWRITE)
            except FileNotFoundError as dummy:
                _utilLogger.log(logging.DEBUG, "writeperm: cannot find " + str(folder))
                pass
    os.chmod(pathtodir, stat.S_IWRITE)


def pebinarytype(unknownpefile):
    '''
    Returns a tuple (file extension, TYPE)
    '''
    if unknownpefile.is_exe():
        return 'EXE', 'application'
    elif unknownpefile.is_driver():
        return 'SYS', 'system driver'
    elif unknownpefile.is_dll():
        return 'DLL', 'dynamic-link library'

    return 'UNKNOWN', 'UNKNOWN'


def getpearch(unknownpefile):
    '''
    Find Architecture
    '''
    foundarch = "UNKNOWN"
    machinearch = getattr(unknownpefile.NT_HEADERS.FILE_HEADER, "Machine", None)

    if machinearch is not None:
        for arch in PEARCH:
            if machinearch == arch:
                foundarch = PEARCH[arch]

    return foundarch


def getpesigwoage(unknownpefile):
    '''
    PE with no age
    '''
    guidstr = 'NOTFOUND'
    debugentry = getattr(unknownpefile, "DIRECTORY_ENTRY_DEBUG", None)
    if debugentry is not None:
        for entry in unknownpefile.DIRECTORY_ENTRY_DEBUG:
            if entry.struct.dump_dict()['Type']['Value'] ==          \
               pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']:
                pdb2exist = getattr(entry.entry, "CvHeaderSignature", None)

                if pdb2exist is not None:
                    return str(hex(entry.entry.Signature))

                pdb7exist = getattr(entry.entry, "CvSignature", None)
                if pdb7exist is not None:
                    data4 = entry.entry.Signature_Data4
                    data4h = data4.from_bytes(
                        data4.to_bytes(2, byteorder='big'), byteorder='little')
                    data5 = entry.entry.Signature_Data5
                    data5h = data5.from_bytes(
                        data5.to_bytes(2, byteorder='big'), byteorder='little')
                    data6 = entry.entry.Signature_Data6
                    data6h = data6.from_bytes(
                        data6.to_bytes(4, byteorder='big'), byteorder='little')

                    guidstr = ("{:08x}-{:04x}-{:04x}-{:04x}-" +
                               "{:04x}{:08x}").format(
                                   entry.entry.Signature_Data1,
                                   entry.entry.Signature_Data2,
                                   entry.entry.Signature_Data3,
                                   data4h, data5h, data6h)
                    guidstr = "{" + guidstr.upper() + "}"
    else:
        global _utilLogger
        _utilLogger.log(logging.DEBUG, "-- GUID not found....")
        pass

    return guidstr


def getpeage(unknownpefile):
    '''
    PE age
    '''
    age = -1
    debugentry = getattr(unknownpefile, "DIRECTORY_ENTRY_DEBUG", None)
    if debugentry is not None:
        for entry in unknownpefile.DIRECTORY_ENTRY_DEBUG:
            if entry.struct.dump_dict()['Type']['Value'] ==          \
             pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']:
                attrage = getattr(entry.entry, "Age", None)

                if attrage is None:
                    return age

                age = attrage
    else:
        global _utilLogger
        _utilLogger.log(logging.DEBUG, "-- Age not found....")
        pass
    return age


def getpepdbfilename(unknownpefile):
    '''
    pe pdbfilename
    '''
    pdbfilename = 'NOTFOUND'
    debugentry = getattr(unknownpefile, "DIRECTORY_ENTRY_DEBUG", None)
    if debugentry is not None:
        for entry in unknownpefile.DIRECTORY_ENTRY_DEBUG:
            if entry.struct.dump_dict()['Type']['Value'] ==          \
             pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']:
                attrpdbfilename = getattr(entry.entry, "PdbFileName", None)

                if attrpdbfilename is None:
                    return pdbfilename

                pdbfilename = attrpdbfilename.decode('ascii')
                try:
                    pdbfilename = pdbfilename[:pdbfilename.index('\x00')]
                except ValueError as dummy:
                    pass
    else:
        global _utilLogger
        _utilLogger.log(logging.DEBUG, "-- Pdbfilename not found....")
        pass
    return pdbfilename

def ispe(file):
    '''
    checks for valid PE file
    '''
    try:
        petemp = pefile.PE(file, fast_load=False)
        petemp.close()
    except (pefile.PEFormatError, IOError):
        return False
    return True


def ispedbgstripped(file):
    '''
    checks to see if PE debug information was stripped and placed into dbg file.
    '''
    unknownpefile = pefile.PE(file)

    filehdr = getattr(unknownpefile, "FILE_HEADER", None)
    if filehdr is not None:
        characteristics = getattr(unknownpefile, "Characteristics", None)
        unknownpefile.close()
        if characteristics is not None:
    # https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_file_header
    # IMAGE_FILE_DEBUG_STRIPPED
            if (characteristics & 0x0200) == 0x0200:
                return True
    return False


def ispebuiltwithdebug(pebinary):
    '''
    check to see if PE was built with debug symbols in a pdb file
    '''
    peitem = pefile.PE(pebinary)

    debugsize = peitem.dump_dict()['Directories'][6]['Size']['Value']
    peitem.close()
    if debugsize == 0:
        return False
    return True


def validatecab(unknownfile):
    '''
    validate CAB file
    '''
    global _utilLogger
    if "wsusscan.cab" in unknownfile.lower() or     \
        "wsusscn2.cab" in unknownfile.lower() or    \
        "wuresdist.cab" in unknownfile.lower() or   \
            "muauth.cab" in unknownfile.lower():
        _utilLogger.log(logging.DEBUG, "{-} Ignoring " + unknownfile + "...")
        return False
    elif unknownfile.endswith(".cab") or unknownfile.endswith(".msu"):
        try:
            with open(unknownfile, 'rb') as file:
                magic = file.read(4)
                # file signature for MS CABs. Some files ending with .CAB
                # may actually be a ZIP file
                if not magic == b"\x4d\x53\x43\x46":
                    return False
                else:
                    return True
        except FileNotFoundError as ferror:
            _utilLogger.log(logging.DEBUG, "{-} validatecab: Could not open " + str(unknownfile) + " " + \
                   str(ferror.strerror) + " (" + str(ferror.winerror) + ")")
            return False
        except OSError as oserror:
            _utilLogger.log(logging.DEBUG, "{-} validatezip: Issue found for " + str(unknownfile) + " " + \
                str(oserror))
            return None
    else:
        return False

def validatezip(unknownfile):
    '''
    some CABs/MSUs may exactly be ZIPs
    '''
    global _utilLogger

    if unknownfile.endswith(".cab") or unknownfile.endswith(".msu"):
        try:
            with open(unknownfile, 'rb') as file:
                magic = file.read(4)
                # file signature for MS CABs. Some files ending with .CAB
                # may actually be a ZIP file
                if not (magic == b"\x50\x4b\x03\x04" or \
                    magic == b"\x50\x4b\x05\x06" or \
                    magic == b"\x50\x4b\x07\x08"):
                    return False
                else:
                    return True
        except FileNotFoundError as ferror:
            _utilLogger.log(logging.DEBUG, "{-} validatezip: Could not open " + str(unknownfile) + " " + \
                   str(ferror.strerror) + " (" + str(ferror.winerror) + ")")
            return False
        except OSError as oserror:
            _utilLogger.log(logging.DEBUG, "{-} validatezip: Issue found for " + str(unknownfile) + " " + \
                str(oserror))
            return None
    else:
        return False


def getfilehashes(jobfile):
    '''
    return a tuple of string hash values for a file
    '''
    from hashlib import sha256
    from hashlib import sha1
    global _utilLogger

    hashes = None

    try:
        with open(str(jobfile), 'rb') as item:
            buf = item.read()
            hashes = (sha256(buf).hexdigest(), sha1(buf).hexdigest())
    except FileNotFoundError as ferror:
        _utilLogger.log(logging.DEBUG, "{-} getfilehashes: Could not open " + str(jobfile) + " " + \
            str(ferror.strerror) + " (" + str(ferror.winerror) + ")")
        return None
    except OSError as oserror:
        _utilLogger.log(logging.DEBUG, "{-} getfilehashes: Issue found for " + str(jobfile) + " " + \
            str(oserror))
        return None

    return hashes

def verifyhex(filedigest):
    hexfiledigest = None
    
    if isinstance(filedigest, bytes):
        hexfiledigest = filedigest.hex().upper()
        hexfiledigest = "0x" + hexfiledigest
    else:
        try:
            hexfiledigest = str(hex(int(filedigest, 16))).upper().replace('X', 'x')
        except ValueError:
            return hexfiledigest
    
    return hexfiledigest