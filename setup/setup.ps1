<#
    .SYNOPSIS
    downloads prerequisites and sets up and organizes files for BAM!

    .DESCRIPTION
    downloads prerequisites and sets up and organizes files for BAM! Prerequisites include Windows Debugging Tools, Python 3.7+, and 7-zip

    .INPUTS
    None. Not made to be compatible with piped inputs.

    .OUTPUTS
    None. Not made to be compatible with piping output to other commandlets.
#>
Set-Content -Path $install_log -Value "BAM! installation log"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# check if Windows Debugging tools are installed.
$dbgTools = (Test-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots')

if (($false -eq $dbgTools) )
{
    Add-Content -Path ".\wsdk_install_log.txt" -Value "Windows Debugging Tools not detected. Downloading and Installing WDK."

    $wdkDownloadPage = Invoke-WebRequest -Uri 'https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/'
    $downloadURI = ""
    foreach ($link in $wdkDownloadPage.Links)
    {
        if ($null -ne ($link.outerHTML | Select-String -Pattern "installer"))
        {
            $downloadURI = $link.href
        }
    }

    # get Windows Sdk Debugging Toolkit prerequisite; currently uses a direct link, but should figure out how to always download the latest version?
    Invoke-WebRequest -Uri $downloadURI -OutFile '.\windsdksetup.exe'
    Start-Process -FilePath .\windsdksetup.exe -ArgumentList "/features OptionId.WindowsDesktopDebuggers /quiet /log `".\wsdk_install_log.txt`"" -Wait
}
else
{
    # Tools version check
    $toolsVersionReg = Get-ChildItem -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots'
    $highestVersion = [System.Version]'0.0.0'
    foreach ($rawver in $toolsVersionReg.Name)
    {
        $ver = ($rawver -split "\\")[-1]
        if ([System.Version]$ver -gt $highestVersion)
        {
            $highestVersion = [System.Version]$ver
        }
    }
    if ($highestVersion -lt [System.Version]'10.0.17763')
    {
        Add-Content -Path ".\wsdk_install_log.txt" -Value "Windows Debugging Tools invalid version detected. Downloading and Installing WDK."

        $wdkDownloadPage = Invoke-WebRequest -Uri 'https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/'
        $downloadURI = ""
        foreach ($link in $wdkDownloadPage.Links)
        {
            if ($null -ne ($link.outerHTML | Select-String -Pattern "installer"))
            {
                $downloadURI = $link.href
            }
        }

        # get Windows Sdk Debugging Toolkit prerequisite
        Invoke-WebRequest -Uri $downloadURI -OutFile '.\windsdksetup.exe'
        Start-Process -FilePath .\windsdksetup.exe -ArgumentList "/features OptionId.WindowsDesktopDebuggers /quiet /log `".\wsdk_install_log.txt`"" -Wait
    }
}


$dbtoolsPath = (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots' -Name 'WindowsDebuggersRoot10') + 'x64'

# copy the necessary symbol checking files to tools directory
Copy-Item -Path "$dbtoolsPath\symchk.exe" -Destination '..\tools\x64'
Copy-Item -Path "$dbtoolsPath\SymbolCheck.dll" -Destination '..\tools\x64'
Copy-Item -Path "$dbtoolsPath\symsrv.dll" -Destination '..\tools\x64'
Copy-Item -Path "$dbtoolsPath\symsrv.yes" -Destination '..\tools\x64'

# check for python version >= 3.7
$pythonPathCheck = (Test-Path -Path 'HKLM:\SOFTWARE\Python\PythonCore')

if (($false -eq $pythonPathCheck))
{
    Add-Content -Path ".\python_install_log.txt" -Value "Python 3.7+ not detected. Downloading and Installing Python."

    $pythonDownloadPage = Invoke-WebRequest -Uri 'https://www.python.org/downloads'
    $downloadURI = ""
    foreach ($link in $pythonDownloadPage.Links)
    {
        if ($null -ne ($link.outerHTML | Select-String -Pattern "-amd64.exe"))
        {
            $downloadURI = $link.href
        }
    }

    # download and install latest Python
    Invoke-WebRequest -Uri $downloadURI -OutFile '.\python-3.11.4-amd64.exe'

    # should potentiall reconsider whether to do this for everyone or not
    Start-Process -FilePath .\python-3.11.4-amd64.exe -ArgumentList "/quiet PrependPath=1 InstallAllUsers=1 Include_doc=0 Shortcuts=0 Include_tcltk=0 /log `".\python_install_log.txt`"" -Wait
}
else
{
    # Tools version check
    $pythonVersionReg = Get-ChildItem -Path 'HKLM:\SOFTWARE\Python\PythonCore'
    $highestVersion = [System.Version]'0.0.0'
    foreach ($rawver in $pythonVersionReg.Name)
    {
        $ver = Get-ItemProperty $rawver -Name 'Version'
        if ([System.Version]$ver -gt $highestVersion)
        {
            $highestVersion = [System.Version]$ver
        }
    }
    if ($highestVersion -lt [System.Version]'3.7')
    {
        Add-Content -Path ".\python_install_log.txt" -Value "Incorrect Python version detected. Downloading and Installing Latest Python."

        $pythonDownloadPage = Invoke-WebRequest -Uri 'https://www.python.org/downloads'
        $downloadURI2 = ""
        foreach ($link in $pythonDownloadPage.Links)
        {
            if ($null -ne ($link.outerHTML | Select-String -Pattern "-amd64.exe"))
            {
                $downloadURI2 = $link.href
            }
        }

        # download and install latest Python
        Invoke-WebRequest -Uri $downloadURI2 -OutFile '.\python-3.11.4-amd64.exe'

        # should potentiall reconsider whether to do this for everyone or not
        Start-Process -FilePath .\python-3.11.4-amd64.exe -ArgumentList "/quiet PrependPath=1 InstallAllUsers=1 Include_doc=0 Shortcuts=0 Include_tcltk=0 /log `".\python_install_log.txt`"" -Wait
    }
}

# install python prerequisite modules
$pythonpath = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Python\PythonCore\3.11\InstallPath' -Name 'ExecutablePath'
Start-Process -FilePath $pythonpath -ArgumentList "-m pip install -r .\requirements.txt --log .\python_install_log.txt" -Wait

# enable the Windows Long Paths setting
$longPathTest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled"
if ($null -eq $longPathTest)
{
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
}
elseif ($longPathTest -eq 0)
{
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -Force
}

# check for 7-zip
$seven_zip = Test-Path -Path 'HKLM:\SOFTWARE\7-Zip'

if ($seven_zip -eq $false)
{
    Add-Content -Path ".\7-zip_install_log.txt" -Value "7-zip not detected. Downloading and Installing 7-zip."
    # download and install 7-zip
    Invoke-WebRequest -Uri 'https://7-zip.org/a/7z2301-x64.exe' -OutFile '.\7z2301-x64.exe'

    Start-Process -FilePath .\7z2301-x64.exe -ArgumentList "/S /D=`"C:\Program Files\7-Zip`"" -Wait
}

# install WSUS and minimally configure
New-Item -Path C:\Wsus_Updates -ItemType Directory
Install-WindowsFeature -Name UpdateServices -LogPath ".\WSUS_install_log.txt"
Start-Process -FilePath 'C:\Program Files\Update Services\Tools\wsusutil.exe' -ArgumentList "postinstall CONTENT_DIR=C:\Wsus_Updates"