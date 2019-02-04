Param(
    [parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $binarypath
)

#requires -Version 5
Set-StrictMode -Version 5

<#
    Script is part of BAM! project to assist in identifying other information on PE files
#>

<#
Certificate Chains - https://blogs.msdn.microsoft.com/timid/2013/04/23/certificate-chains/
#>
function Get-CertificateTrustChain { 
     <# 
     .synopsis 
     Returns list of X.509 certificates for specified X.509 certificate and trust chain. 
  
     .description 
     Uses .NET methods to build a trust chain for the specified X.509 certificate.  The chain is returned as an array of certificates. The first element of the array is the specified X.509 certificate itself.  The last element is the root CA (e.g.: GTE CyberTrust) 
  
     .parameter certificate 
     Certificate for which to validate the trust chain.  The value can be either a path to a file, or an X509 object. 
  
     .parameter help 
     Show this text and exit. 
  
     .Inputs 
     [object] Certificate 
  
     .Outputs 
     [X509Certificate2[]] X.509 certificates. 
  
     .Link 
     http://msdn.microsoft.com/en-us/library/vstudio/system.security.cryptography.x509certificates.x509chain.build.aspx 
     http://msdn.microsoft.com/en-us/library/vstudio/system.security.cryptography.x509certificates.x509chain.chainelements.aspx 
     #> 
  
     param ( 
         [Parameter(ValueFromPipeline=$true,Position=0)][Object]$certificate, 
         [switch]$help 
     ); 
     begin { 
         if ($help) { Get-Help Get-CertificateTrustChain -Full | more; return; } 
         $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain; 
  
     } 
  
     process { 
         if ($certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { 
             #noop 
         } elseif (Test-Path $certificate) { 
             try { 
                 $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certificate; 
             } 
             catch [Exception]{ 
                 Write-Warning "Unable to cast path '$certificate' to X509Certificate2 object."; 
                 $cert = $null; 
             } 
         } 
         if ($certificate) { 
             Write-Progress -Activity "Building trust chain for" -Status ("$($certificate.Subject) ($($certificate.Thumbprint))"); 
             $chain.Build($certificate) | Out-Null; 
             if ( $chain.ChainElements ) { 
                 $chain.ChainElements | % { $_.Certificate; } 
             } else { 
                 Write-Warning "Unable to verify certificate chain for certificate with thumbprint $($certificate.Thumbprint)." 
             } 
         } 
     } 
}

function Get-BAMCertInfo($binarypath){

    $authsig = Get-AuthenticodeSignature -FilePath $binarypath
    # Get-AuthenticodeSignature returns System.Management.Automation.Signature: https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.signature?view=powershellsdk-1.1.0
    # SignatureType could be 0 (None/not signed), 1 (Authenticode/embedded signature), or 2 (Catalog/catalog signature)
    # https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.signaturetype?view=powershellsdk-1.1.0

    $signercount = 0
    $timecount = 0
    $SignerCertificateName = ''
    $SignerCertificateFriendlyName = ''
    $SignerCertificateIssuer = ''
    $SignerCertificateSerialNumber = ''
    $SignerCertificateNotBefore = ''
    $SignerCertificateNotAfter = ''
    $SignerCertificateThumbprint = ''
    $TimeStamperCertificateSubject = ''
    $TimeStamperCertificateFriendlyName = ''
    $TimeStamperCertificateIssuer = ''
    $TimeStamperCertificateSerialNumber = ''
    $TimeStamperCertificateNotBefore = ''
    $TimeStamperCertificateNotAfter = ''
    $TimeStamperCertificateThumbprint = ''

    if($authsig.SignatureType -ne 0){
        $signercount = ($authsig.SignerCertificate | Get-CertificateTrustChain  | measure-object).count
        $timecount = ($authsig.TimeStamperCertificate | Get-CertificateTrustChain  | measure-object).count

        $SignerCertificateName = $authsig.SignerCertificate.Subject
        $SignerCertificateFriendlyName = $authsig.SignerCertificate.FriendlyName
        $SignerCertificateIssuer = $authsig.SignerCertificate.GetIssuerName()
        $SignerCertificateSerialNumber = $authsig.SignerCertificate.GetSerialNumberString()
        $SignerCertificateNotBefore = $authsig.SignerCertificate.GetEffectiveDateString()
        $SignerCertificateNotAfter = $authsig.SignerCertificate.GetExpirationDateString()
        $SignerCertificateThumbprint = $authsig.SignerCertificate.GetCertHashString()
        $TimeStamperCertificateSubject = $authsig.TimeStamperCertificate.Subject
        $TimeStamperCertificateFriendlyName = $authsig.TimeStamperCertificate.FriendlyName
        $TimeStamperCertificateIssuer = $authsig.TimeStamperCertificate.GetIssuerName()
        $TimeStamperCertificateSerialNumber = $authsig.TimeStamperCertificate.GetSerialNumberString()
        $TimeStamperCertificateNotBefore = $authsig.TimeStamperCertificate.GetEffectiveDateString()
        $TimeStamperCertificateNotAfter = $authsig.TimeStamperCertificate.GetExpirationDateString()
        $TimeStamperCertificateThumbprint = $authsig.TimeStamperCertificate.GetCertHashString()
    }

    $date = Get-Date
    $fname = ([string]$date.Ticks + ".xml") 
    $authsig | Export-CliXml -Path $fname
    $objdata = -join ((Get-Content $fname) -replace '(^\s+|\s+$)','' -replace '\s+',' ' -replace '`n|`r','')

    $PsObject = New-Object PSObject -Property @{            
            Name = $authsig.path
            Status = $authsig.Status
            StatusMessage = $authsig.StatusMessage
            SignatureType = $authsig.SignatureType
            IsOSBinary = $authsig.IsOSBinary
            SignerCertificateName = $SignerCertificateName
            SignerCertificateFriendlyName = $SignerCertificateFriendlyName
            SignerCertificateIssuer = $SignerCertificateIssuer
            SignerCertificateSerialNumber = $SignerCertificateSerialNumber
            SignerCertificateNotBefore = $SignerCertificateNotBefore
            SignerCertificateNotAfter = $SignerCertificateNotAfter
            SignerCertificateThumbprint = $SignerCertificateThumbprint
            TimeStamperCertificateSubject = $TimeStamperCertificateSubject
            TimeStamperCertificateFriendlyName = $TimeStamperCertificateFriendlyName
            TimeStamperCertificateIssuer = $TimeStamperCertificateIssuer
            TimeStamperCertificateSerialNumber = $TimeStamperCertificateSerialNumber
            TimeStamperCertificateNotBefore = $TimeStamperCertificateNotBefore
            TimeStamperCertificateNotAfter = $TimeStamperCertificateNotAfter
            TimeStamperCertificateThumbprint = $TimeStamperCertificateThumbprint
            NumberOfCertsInSignerChain = $signercount
            NumberOfCertsInTimeStampChain = $timecount
            PsObjData = $objdata
        }

    Remove-Item $fname
    $PsObject | ConvertTo-Json
}

Get-BAMCertInfo($binarypath)