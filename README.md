# BAM - Binary Analysis Metadata

"You just throw it in and BAM! It works!"

The Binary Analysis Metadata (BAM!) tool collects and analyzes Windows updates, binaries, and symbol files. File metadata is then compiled into a SQLite3 database file which can be easily be connected to and queried. The overall goal of BAM is to provide files and data to security researchers, analysts, and reverse engineers in a convenient repository, allowing them to cut down on the analytic overhead of collecting all the right files for themselves.

## Design

### Goal

Develop a tool that can scan Windows updates, store information about those updates, obtain symbols for binary files, and analyze said information

### Requirements

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

* Python 3.7+ 64-bit - <https://www.python.org/downloads/>
  * pefile - <https://github.com/erocarrera/pefile>
  * pyodbc (optional) - <https://github.com/mkleehammer/pyodbc>
  * SQLite3
  * defusedxml
* 7zip - https://www.7-zip.org/
* Windows Debugging Tools (found in Windows SDK) - <https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools>
* Windows Server Update Services (WSUS)  - Add role in Windows Server 2016+ (core or GUI) <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2016>
* Python SQL Driver - pyodbc - <https://docs.microsoft.com/en-us/sql/connect/python/python-driver-for-sql-server?view=sql-server-2017>

## Usage

### Setup

Once the prerequisites are installed, simply run the setup.cmd script in the setup folder to allow the tool to move files into relevant folders.
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
py.exe main.py -c -p "path to updates" -pd "path to extract files to" -sl -ss "directory path to symstore location or symbol location" -sp "path to where syms are to be stored"
```

When dealing with updadtes of Windows 10 Version 1809 and later use the '-pb' switch to specify where Windows 10 base file version are located, ie:
```cmd
py.exe main.py -x -p "path to updates" -pd "path to extract files to" -pb "path to base files" -sp "path to where syms are to be stored"
```
ideally, base files should be organized by the major version (1809, 1903, 20h2, etc.) in separate directories within the base files directory.