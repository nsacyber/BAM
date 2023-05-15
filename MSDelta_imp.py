# implementation of MSDelta API to handle new 

from ctypes import windll, wintypes, c_size_t, pointer, Structure, Union, c_int64, cast, POINTER, c_ubyte, c_ulong, GetLastError
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

    ApplyDeltaGetReverseB = windll.msdelta.ApplyDeltaGetReverseB
    # args in order of flag, base struct, patch struct, file timestamp of patch file, target output struct, reverse patch for target output struct
    ApplyDeltaGetReverseB.argtypes = [DELTA_FLAG_TYPE, Delta_Input, Delta_Input, POINTER(wintypes.FILETIME), POINTER(Delta_Output), POINTER(Delta_Output)]
    ApplyDeltaGetReverseB.restype = wintypes.BOOL

# other functions and structures, potentially taken from a hodgepodge of other windows dlls
class misc_imports:
    # class Security_Descriptor(Structure):
    #     # Control is of type SECURITY_DESCRIPTOR_CONTROL which is represented as a WORD
    #     _fields_ = [('Revision', wintypes.BYTE), ('Sbz1', wintypes.BYTE), ('Control', wintypes.WORD), ('Owner', )]
    GetFileTime = windll.kernelbase.GetFileTime
    # args in order of handle to file, create time, las access time, last write time
    GetFileTime.argtypes = [wintypes.HANDLE, wintypes.LPFILETIME, wintypes.LPFILETIME, wintypes.LPFILETIME]
    GetFileTime.restype = wintypes.BOOL

    CreateFileA = windll.kernelbase.CreateFileA
    # args in order of file name to access/create, desired access, share mode, creation disposition, flags and attributes
    CreateFileA.argtypes = [wintypes.LPCSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    CreateFileA.restype = wintypes.HANDLE


def delta_patch(base: str, patch: str) -> tuple:
    # apply a single patch to a file and return status (-1 is crc failed, 0 is bad, 1 is good), byte array of contents,
    # and size of contents.

    with open(patch, 'rb') as file:
        # first check crc, then begin building delta input files
        filebuf = file.read()

        file_contents = filebuf[4:]
        crc = int.from_bytes(filebuf[:4], 'little')
        filecrc = zlib.crc32(file_contents)

        if not filecrc == crc:
            return -1, None
    
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
        # -2 indicates error in type of base file, must be string or bytes
        return -2, None

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
        # Error code 1 indicates incorrect function? it would seem that this error code ocurring would be extremely unlikely, so don't think that it would be necessary to change this return value.
        return GetLastError(), None
    return_buf = bytes((c_ubyte*output.uSize).from_address(output.lpstart))
    delta_imports.DeltaFree(output.lpstart)

    return status, return_buf
    
def patch_binary(current: str, forward: str, reverse: str, output: str, null: str=None) -> tuple:
    # apply full patch to obtain desired binary for analysis

    returnError = None
    # if applying a null differential, just do that and skip everything else
    if null is not None:
        status1, final = delta_patch(None, null)
        if not status1 == 1:
            error1 = ctypes.GetLastError()
            return status1, error1
    else:
        # first apply reverse to current
        status2, base = delta_patch(current, reverse)
        if not status2 == 1:
            error2 = ctypes.GetLastError()
            returnError = error2
        
        # then apply forward to base
        status3, final = delta_patch(base, forward)
        if not status3 == 1:
            error3 = ctypes.GetLastError()
            returnError = error3

        if not (status2 == 1 or status3 == 1):
            return status3, returnError

    
    # if all goes well, write to file and return that
    with open(output, 'wb') as file:
        file.write(final)

    return 0, None

def Win11_patch_binary(base: str, forward: str) -> tuple:
    
    # basename = cast(base, wintypes.LPCSTR)
    # access = c_ulong(2147483648)                    # GENERIC READ ACCESS
    # sharemode = c_ulong(0)                          # NO SHARING
    # creationdisposition = c_ulong(3)                # OPEN_EXISTING
    # f_and_a = c_ulong(128)                          # FILE_ATTRIBUTE_NORMAL
    # basehandle = misc_imports.CreateFileA(basename, access, sharemode, creationdisposition, f_and_a)

    # print(basehandle)

    # createTime = wintypes.LPFILETIME()
    # accessTime = wintypes.LPFILETIME()
    # writeTime = wintypes.LPFILETIME()
    # status = misc_imports.GetFileTime(basehandle, createTime, accessTime, writeTime)

    # if not status:
    #     return GetLastError()
    
    # return createTime

    with open(forward, 'rb') as file:
        contents = file.read()

        # chop off crc if it exists until we get to the file signature of PA30. Will worry about checking the CRC later.
        while not contents[0:4] == 'PA30'.encode(encoding='ascii'):
            contents = contents[4:]

        delta_filetime = wintypes.FILETIME()
        delta_filetime.dwHighDateTime = c_ulong(int.from_bytes(contents[8:12]))
        delta_filetime.dwLowDateTime = c_ulong(int.from_bytes(contents[4:8]))
        lp_delta_filetime = wintypes.LPFILETIME(delta_filetime)

        forward_delta = Delta_Input()
        forward_delta.lpcstart = cast(contents, wintypes.LPCVOID)
        forward_delta.uSize = len(contents)
        forward_delta.Editable = False

    with open(base, 'rb') as file:
        contents = file.read()

        base_delta = Delta_Input()
        base_delta.lpcstart = cast(contents, wintypes.LPCVOID)
        base_delta.uSize = len(contents)
        base_delta.Editable = False

    output_buffer = Delta_Output()
    reverse_buffer = Delta_Output()

    status = delta_imports.ApplyDeltaGetReverseB(delta_imports.DELTA_FLAG_NONE, base_delta, forward_delta, lp_delta_filetime, pointer(output_buffer), pointer(reverse_buffer))

    if not status == 1:
        return GetLastError(), None, None
    return status, output_buffer, reverse_buffer

