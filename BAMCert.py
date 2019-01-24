import subprocess as sp
import argparse
import winreg

from db import wsuse_db
        

class Certificate():
    def __init__(self, issuee, issuer, expiration, sha1):
        self.issuee = issuee
        self.issuer = issuer
        self.expiration = expiration
        self.sha1 = sha1

    def __str__(self):
        ostr = ""
        ostr = ostr + "Issued to: " + str(self.issuee) + "\n"
        ostr = ostr + "Issued by: " + str(self.issuer) + "\n"
        ostr = ostr + "Expiration: " + str(self.expiration) + "\n"
        ostr = ostr + "SHA1 hash: " + str(self.sha1) + "\n"
        return ostr
    
if __name__ == "__main__":
    # do cert checking stuff here ???

    pefile = "C:\\Windows\\System32\\aadtb.dll"
    signpath = None
    try:
        key1 = winreg.OpenKeyEx(key=winreg.HKEY_LOCAL_MACHINE, sub_key="SOFTWARE")
        key2 = winreg.OpenKeyEx(key=key1, sub_key="WOW6432Node")
        key3 = winreg.OpenKeyEx(key=key2, sub_key="Microsoft")
        key4 = winreg.OpenKeyEx(key=key3, sub_key="Microsoft SDKs")
        key5 = winreg.OpenKeyEx(key=key4, sub_key="Windows")
        key6 = winreg.OpenKeyEx(key=key5, sub_key="v10.0")
        signpath = winreg.QueryValueEx(key6, "InstallationFolder")[0]
        signpath = signpath + "bin\\" + winreg.QueryValueEx(key6, "ProductVersion")[0] + ".0\\x64\\signtool.exe"
        # the .0 is necessary because that's how the folder is named on the system apparently
        winreg.CloseKey(key1)
        winreg.CloseKey(key2)
        winreg.CloseKey(key3)
        winreg.CloseKey(key4)
        winreg.CloseKey(key5)
        winreg.CloseKey(key6)
    except OSError:
        import sys
        sys.exit("Exception occurred when searching for Windows SDK. SDK is probably not installed.")

    args = signpath + " verify /a /v " + str(pefile)
    parsedoutput = None

    with sp.Popen(args, shell=False, stdout=sp.PIPE, stderr=sp.PIPE) as signtool:
        rawout, dummy = signtool.communicate()

        parsedoutput = rawout.decode("ascii")

    catfile = None
    signcertchain = []
    timestamp = None
    timecertchain = []
    lastnonsigblock = None
    filehash = None
    for block in parsedoutput.split("\r\n\r\n"):
        block = block.lstrip()
        blocklines = block.split("\n")
        blocklines.append(" ")
        if "Signing Certificate Chain" in blocklines[0]:
            lastnonsigblock = "chain"
            issuee = blocklines[1].lstrip().replace("Issued to: ", "")
            issuer = blocklines[2].lstrip().replace("Issued by: ", "")
            expiration = blocklines[3].lstrip().replace("Expires:   ", "")
            sha1 = blocklines[4].lstrip().replace("SHA1 hash: ", "")
            cert = Certificate(issuee, issuer, expiration, sha1)
            signcertchain.append(cert)
        elif "timestamped" in blocklines[0]:
            lastnonsigblock = "timestamp"
            timestamp = blocklines[0][30:]
            issuee = blocklines[2].lstrip().replace("Issued to: ", "")
            issuer = blocklines[3].lstrip().replace("Issued by: ", "")
            expiration = blocklines[4].lstrip().replace("Expires:   ", "")
            sha1 = blocklines[5].lstrip().replace("SHA1 hash: ", "")
            cert = Certificate(issuee, issuer, expiration, sha1)
            timecertchain.append(cert)
        elif "File is signed in catalog:" in blocklines[1]:
            catfile = blocklines[1].lstrip("File is signed in catalog:")
            filehash = blocklines[2].split(" ")[-1]
        elif "Signature Index" in blocklines[0]:
            filehash = blocklines[1].split(" ")[-1]
        elif "Issued" in blocklines[0] and lastnonsigblock == "chain":
            issuee = blocklines[0].lstrip().replace("Issued to: ", "")
            issuer = blocklines[1].lstrip().replace("Issued by: ", "")
            expiration = blocklines[2].lstrip().replace("Expires:   ", "")
            sha1 = blocklines[3].lstrip().replace("SHA1 hash: ", "")
            cert = Certificate(issuee, issuer, expiration, sha1)
            signcertchain.append(cert)
        elif "Issued" in blocklines[0] and lastnonsigblock == "timestamp":
            issuee = blocklines[0].lstrip().replace("Issued to: ", "")
            issuer = blocklines[1].lstrip().replace("Issued by: ", "")
            expiration = blocklines[2].lstrip().replace("Expires:   ", "")
            sha1 = blocklines[3].lstrip().replace("SHA1 hash: ", "")
            cert = Certificate(issuee, issuer, expiration, sha1)
            timecertchain.append(cert)
        else:
            # block doesn't have any information we need so skip
            continue

    print("cert info:")
    print("SHA256 hash: " + str(filehash))
    print("catalog: " + str(catfile))
    print("timestamp: " + str(timestamp))
    print("Signing certificate chain:\n")
    for cert in signcertchain:
        print(cert)
    print("timestamp verification chain:\n")
    for cert in timecertchain:
        print(cert)
