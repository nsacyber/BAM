# implementation of MSDelta API to handle new 

from ctypes import windll, wintypes, c_size_t, pointer, Structure, Union, c_int64, cast, POINTER, c_ubyte, GetLastError
import ctypes
from os import error
import zlib

# structures needed for patching
class Delta_Input(Structure):
    class buffer_union(Union):
        _fields_ = [('lpcstart', wintypes.LPCVOID), ('lpstart', wintypes.LPVOID)]
    _anonymous_ = ('buf_u',)
    _fields_ = [('buf_u', buffer_union), ('uSize', c_size_t), ('Editable', wintypes.BOOL)]

class Delta_Output(Structure):
    _fields_ = [('lpstart', wintypes.LPVOID),('uSize',c_size_t)]

# values and functions taken from MSDelta
class delta_imports:
    DELTA_FLAG_TYPE = c_int64
    DELTA_FLAG_NONE = 0x0000000000000000
    DELTA_FLAG_ALLOW_PA19 = 0x0000000000000001

    ApplyDeltaB = windll.msdelta.ApplyDeltaB
    # args in order of flag, base struct, patch struct, output struct
    ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, Delta_Input, Delta_Input, POINTER(Delta_Output)]
    ApplyDeltaB.restype = wintypes.BOOL

    DeltaFree = windll.msdelta.DeltaFree
    # meant to free the output struct
    DeltaFree.argtypes = [wintypes.LPVOID]
    DeltaFree.restype = wintypes.BOOL

def delta_patch(base, patch):
    # apply a single patch to a file and return status? (-1 is crc failed, 0 is good, 1 is other), byte array of contents,
    # and size of contents.

    with open(patch, 'rb') as file:
        # first check crc, then begin building delta input files
        filebuf = file.read()

        file_contents = filebuf[4:]
        crc = int.from_bytes(filebuf[:4], 'little')
        filecrc = zlib.crc32(file_contents)

        print('crc from file: ', crc, '\ncalculated crc: ', filecrc)

        if not filecrc == crc:
            return -1
    
    delta_in = Delta_Input()
    delta_in.lpcstart = cast(file_contents, wintypes.LPCVOID)
    delta_in.uSize = len(file_contents)
    delta_in.Editable = False

    if type(base) is str:
        with open(base, 'rb') as file2:
            filebuf2 = file2.read()
    elif type(base) is bytes:
        filebuf2 = base
    elif base is None:
        filebuf2 = None
    else:
        print("error in type of base file, must be string or bytes")
        return -2

    base_in = Delta_Input()
    base_in.lpcstart = cast(filebuf2, wintypes.LPCVOID)
    if filebuf2:
        base_in.uSize = len(filebuf2)
    else:
        base_in.uSize = 0
    base_in.Editable = False

    output = Delta_Output()

    status = delta_imports.ApplyDeltaB(delta_imports.DELTA_FLAG_ALLOW_PA19, base_in, delta_in, pointer(output))

    # cleanup the delta buffers
    if not status:
        print("delta_patch failed on ", base, " and ", patch, "with error: ", ctypes.GetLastError())
        return status, base
    return_buf = bytes((c_ubyte*output.uSize).from_address(output.lpstart))
    delta_imports.DeltaFree(output.lpstart)

    return status, return_buf
    
def patch_binary(current, forward, reverse, output, null=None):
    # apply full patch to obtain desired binary for analysis

    returnError1 = None
    returnError2 = None
    # if applying a null differential, just do that and skip everything else
    if null is not None:
        status1, final = delta_patch(None, null)
        if not status1 == 1:
            error1 = ctypes.GetLastError()
            print("error in null patching: ", error1)
            return status1, error1
    else:
        # first apply reverse to current
        status2, base = delta_patch(current, reverse)
        if not status2 == 1:
            error2 = ctypes.GetLastError()
            print("error in reverse patch application: ", error2)
            returnError1 = error2
        
        # then apply forward to base
        status3, final = delta_patch(base, forward)
        if not status3 == 1:
            error3 = ctypes.GetLastError()
            print("error in forward patch application: ", error3)
            returnError2 = error3

        if not (status2 == 1 or status3 == 1):
            print("errors in applying patch: ", returnError1, "\n", returnError2)
            return status3, returnError2

    
    # if all goes well, write to file and return that
    with open(output, 'wb') as file:
        file.write(final)

    return 0, None
