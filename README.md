"You just throw it in and BAM! it works!"

BAM! (Binary Analysis Metadata!) provides the user the ability to collection information on Windows Updates, 
updated files (i.e., PE files), and symbol files. 

Requirements:
* must have the least amount of dependiciaes (portability)
* must be able to run anywhere where python 3.6+ is installed
* must be efficient (threads over process and/or I/O or memory bound) 
* must be compartible to new python versions
* Back by sqlite for quick lookup of patches/PDBs and ability to 
* Microsoft's symsrv.dll and symsrv.yes MUST be placed in \Windows\System32\ by an administrator. 
* Must enable the "Enable Win32 long paths" group policy under "Administrative Templates\System\FileSystem" beginning with Windows 10 v1607 (Anniversary Update)

Microsoft's Symbol Connection and Download EULA:
symchk.exe will prompt the user to accept an Microsoft EULA when a symbol is going to be download from Microsoft's server. The symsrv.yes file (i.e., the YES file) is part of the Windows SDK installation in \Debugger\<arch>\ and is used to silently accept the Microsoft EULA to download the symbols from their servers. You can remove this file to individually accept/denied the EULA. 

"Enable Win32 long paths"
Due to the nature of how Windows updates are structured and named, they are given very long names when decompressed. WSUS Expander will not run unless this group policy is enable

Hardware requiments:
* 32GB of RAM
* 4TB of Disk space (extracted contents and downloaded symbols)
* 2TB of Disk space for WSUS to download everything
* 10 Virtual Processors

Dependencieis:
* Python 3.6+
    pywin32
    pefile
* SQLite
* Windows Server Update Services (WSUS)

* Windows RSAT
* 8GB of RAM (arbitrary minimal)



Goal:
    Develop a tool that can (either on a schedule or manually) scan Windows updates, store
    information about those updates and obtain symbols for updated files.



Use cases:

Create or use current DB, extract files and downloading symbols (initially or continous use): 
py.exe main.py -x -p "<path to updates>" -pd "<path to extract files too>" -ss "<symstore location>" -sp "<path to where syms are to be stored>"
Side note: The script will always attempt to re-download symbols for PE files previously not downloaded.

Create or use current DB, extract files and verify symbols using local symstore 
(initially or continous use): 
py.exe main.py -x -p "<path to updates>" -pd "<path to extract files too>" -sl -ss "<directory path to symstore location or symbol location>" -sp "<path to where syms are to be stored>"

Create or update current DB (requires update file, extracted files, downloaded symbols):
py.exe main.py -c -p "<path to updates>" -pd "<path to extract files too>" -sl -ss "<directory path to symstore location or symbol location>" -sp "<path to where syms are to be stored>"

List total number of PE files within identified updates:

Verify total number of PE files within identified updates match extracted PE files
during two cases:

Populate Update table in DB only (initially or continue use):

Populate Patched table in DB only (initially or continue use):

Populate Symbol table in DB only (initially or continue use):



Knowledge base article describing how to extract .msu files and automate
installing them
- https://blogs.msdn.microsoft.com/astebner/2008/03/11/knowledge-base-article-
    describing-how-to-extract-msu-files-and-automate-installing-them/





