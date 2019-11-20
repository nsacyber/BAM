# BAM - Binary Analysis Metadata

"You just throw it in and BAM! It works!"

The Binary Analysis Metadata (BAM!) tool collects and analyzes Windows updates, binaries, and symbols.

## Design

### Goal

Develop a tool that can scan Windows updates, store information about those updates, obtain symbols for binary files, and analyze said information

### Requirements

* Must have the least amount of dependencies (portability)
* Must be able to run anywhere where python 3.7+ is installed
* Must be efficient (threads over process and/or I/O or memory bound)
* Must be compatible to new python versions
* Backed by SQLite for quick lookup of patches and symbols
* Microsoft's symsrv.dll and symsrv.yes MUST be placed in \Windows\System32\ by an administrator due to symchk.exe's functionality
* Must enable the "Enable Win32 long paths" group policy under "Administrative Templates\System\FileSystem" beginning with Windows 10 1607 (Anniversary Update)
* Must add location of Microsoft Debugging tools to PATH environment variable

## Runtime Requirements

### Microsoft's Symbol Connection and Download EULA

symchk.exe will prompt the user to accept an Microsoft EULA when a symbol is going to be download from Microsoft's server. The symsrv.yes file (i.e., the YES file) is part of the Windows SDK installation in \Debugger\<arch>\ and is used to silently accept the Microsoft EULA to download the symbols from their servers. You can remove this file to individually accept/denied the EULA.

### Group Policy

Enable the **Enable Win32 long paths** policy under **Administrative Templates > System > FileSystem**. Due to the nature of how Windows updates are structured and named, they are given very long names when decompressed. BAM! will not run unless this group policy is enabled. Additionally, to avoid other long name errors during extraction and until the issue is resolved in the program, extract update contents to a single character named directory.

### Hardware

* 32GB of RAM
* 10TB of disk space for extracted contents and downloaded symbols
* 5TB of disk space for WSUS to download updates only (i.e., not OS/feature/service pack upgrades)
* 10 virtual processors

### Dependencies

* Python 3.7+ - <https://www.python.org/downloads/>
  * pefile - <https://github.com/erocarrera/pefile>
  * pyodbc (optional) - <https://github.com/mkleehammer/pyodbc>
  * SQLite3
* 7zip - https://www.7-zip.org/
* Windows Debugging Tools (found in Windows SDK) - <https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools>
* Windows Server Update Services (WSUS)  - Add role in Windows Server 2016+ (core or GUI) <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016>
* Python SQL Driver - pyodbc - <https://docs.microsoft.com/en-us/sql/connect/python/python-driver-for-sql-server?view=sql-server-2017>

## Usage

Display help

```cmd
py.exe main.py
```

Create or use current DB, extract files at *path to updates*, download symbols from Microsoft's symbol server (initially or continuous use) and store them at *path to where syms are to be stored*:

```cmd
py.exe main.py -x -p "path to updates" -pd "path to extract files to" -sp "path to where syms are to be stored"
```

Note: The script will always attempt to re-download symbols for PE files previously not downloaded.

Create or use current DB, extract files and download symbols from a specific symbol server (initially or continuous use):

```cmd
py.exe main.py -x -p "path to updates" -pd "path to extract files to" -ss "symstore location" -sp "path to where syms are to be stored"
```

Note: The script will always attempt to re-download symbols for PE files previously not downloaded.

Create or use current DB, extract files and verify symbols using local symstore (initially or continuous use):

```cmd
py.exe main.py -x -p "path to updates* -pd "path to extract files to" -sl -ss "directory path to symstore location or symbol location" -sp "path to where syms are to be stored"
```

Create or update current DB (requires update file, extracted files, downloaded symbols):

```cmd
py.exe main.py -c -p "path to updates" -pd "path to extract files too" -sl -ss "directory path to symstore location or symbol location" -sp "path to where syms are to be stored"
```
