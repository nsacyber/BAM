# using python 3 with windows server core 1809 as base
FROM python:3

# set environment to powershell
SHELL [ "powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

# Copy BAM files into container
RUN New-Item -Path "C:/Users/Administrator/Documents/BAM" -ItemType "directory"
COPY . C:/Users/Administrator/Documents/BAM

# get and install other requirements
RUN Install-WindowsFeature UpdateServices; \
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::tls12 -bor [Net.SecurityProtocolType]::tls11 -bor [Net.SecurityProtocolType]::tls; \
    Invoke-WebRequest https://download.microsoft.com/download/E/6/B/E6BFDC7A-5BCD-4C51-9912-635646DA801E/en-US/17.5.2.1/x64/msodbcsql.msi -UseBasicParsing -Outfile C:\msodbcsql.msi; \
    msiexec.exe /I "C:\msodbcsql.msi" /passive /qn; \
    Set-ExecutionPolicy RemoteSigned; \
    Invoke-WebRequest https://chocolatey.org/install.ps1 -UseBasicParsing | Invoke-Expression; \
    choco install 7zip -yes; \
    choco install windows-sdk-10.1 -yes;
    
# RUN Invoke-Item "C:/Users/Administrator/Documents/BAM/BAMPSSetup.ps1";
RUN pip install pefile pyodbc

# run setup.cmd to move the rest of the stuff into place
RUN C:\Users\Administrator\Documents\BAM\setup\setup.cmd

# ensure that starting directory is good
WORKDIR C:/Users/Administrator/Documents/BAM

# set up complete, await input?
CMD ["powershell.exe"]