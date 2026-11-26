<#
.SYNOPSIS
    Collecte en lecture seule des artefacts de signature de code sur Windows (labo / IR).

.DESCRIPTION
    Enumere :
      - les certificats des stores CurrentUser\My et LocalMachine\My (cle privee, EKU),
      - les conteneurs de cles Crypto/SystemCertificates,
      - les fichiers candidats (.pfx, .p12, .pvk, .snk, .pem, .key, ...),
      - les scripts/configs qui referencent signtool / Import-PfxCertificate / etc.,
      - l'historique PowerShell (mots-cles),
      - la presence des outils de signature,
      - en option, les evenements 4688 / Sysmon 1 recents.

    Le script ne modifie pas les stores, n'exporte aucune cle privee et ne tente
    aucun mot de passe. Il ecrit uniquement un rapport dans -OutDir.

    A utiliser uniquement sur des machines que vous administrez ou pour
    lesquelles vous avez une autorisation d'investigation.

.PARAMETER Roots
    Racines scannees pour les fichiers. Defaut : profil courant + C:\ProgramData.
    Pour un balayage complet : -Roots C:\Users,C:\ProgramData,C:\Tools

.PARAMETER OutDir
    Dossier du rapport. Defaut : %USERPROFILE%\CertHunt_<timestamp>

.PARAMETER IncludeEvents
    Cherche aussi les executions recentes (Security 4688 / Sysmon 1). Admin requis.

.PARAMETER ShowMatchLines
    Inclut la ligne des correspondances (masquage basique des mots de passe).
    Desactive par defaut pour eviter de recopier des secrets dans le rapport.

.PARAMETER CheckExportable
    Teste l'exportabilite des cles privees. Peut declencher une demande de PIN
    sur une smart card. Desactive par defaut.
#>
[CmdletBinding()]
param(
    [string[]]$Roots = @($env:USERPROFILE, 'C:\ProgramData'),
    [string]$OutDir = (Join-Path $env:USERPROFILE ("CertHunt_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$IncludeEvents,
    [switch]$ShowMatchLines,
    [switch]$CheckExportable
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Hide-Secrets {
    param([string]$Line)
    if (-not $Line) { return '' }
    return ($Line -replace '(?i)(/p\s+|password\s*[=:]\s*|-Password\s+|/csp\s+)(''[^'']*''|"[^"]*"|\S+)', '$1[REDACTED]')
}

function Test-CodeSigningEku {
    param($Cert)
    try {
        $oids = @($Cert.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
        if ($oids -contains '1.3.6.1.5.5.7.3.3') { return $true }
    } catch { }
    try {
        $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
        if ($ext -and ($ext.Format($false) -match 'Code Signing|1\.3\.6\.1\.5\.5\.7\.3\.3')) { return $true }
    } catch { }
    return $false
}

function Get-KeyExportable {
    param($Cert)
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            return $rsa.CspKeyContainerInfo.Exportable
        }
        return 'Unknown (CNG)'
    } catch {
        return 'Unknown/Denied'
    }
}

function Get-OwnerName {
    param([string]$Path)
    try { return (Get-Acl -Path $Path -ErrorAction Stop).Owner } catch { return '' }
}

Write-Host "[*] Collecte des certificats (My)..."
$certRows = @()
foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
    Get-ChildItem $store -ErrorAction SilentlyContinue | ForEach-Object {
        $c = $_
        $eku = ''
        try { $eku = (@($c.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -join ';') } catch { }
        $exportable = ''
        if ($CheckExportable -and $c.HasPrivateKey) { $exportable = Get-KeyExportable $c }
        $certRows += [pscustomobject]@{
            Store          = $store
            Subject        = $c.Subject
            Issuer         = $c.Issuer
            Thumbprint     = $c.Thumbprint
            NotBefore      = $c.NotBefore
            NotAfter       = $c.NotAfter
            HasPrivateKey  = $c.HasPrivateKey
            CodeSigningEku = (Test-CodeSigningEku $c)
            Eku            = $eku
            Exportable     = $exportable
        }
    }
}

Write-Host "[*] Collecte des conteneurs de cles..."
$keyRows = @()
$keyDirs = @(
    "$env:APPDATA\Microsoft\Crypto",
    "$env:APPDATA\Microsoft\SystemCertificates",
    "$env:LOCALAPPDATA\Microsoft\Crypto",
    'C:\ProgramData\Microsoft\Crypto',
    'C:\ProgramData\Microsoft\SystemCertificates'
)
foreach ($dir in $keyDirs) {
    if (Test-Path $dir) {
        Get-ChildItem $dir -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            $keyRows += [pscustomobject]@{
                Path          = $_.FullName
                Length        = $_.Length
                LastWriteTime = $_.LastWriteTime
                Owner         = (Get-OwnerName $_.FullName)
            }
        }
    }
}

Write-Host "[*] Recherche des fichiers candidats..."
$exts = @('.pfx', '.p12', '.pvk', '.spc', '.snk', '.pem', '.key', '.crt', '.cer', '.jks', '.keystore', '.bks')
$fileRows = @()
foreach ($root in $Roots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($ext in $exts) {
        Get-ChildItem $root -Recurse -Force -File -Filter "*$ext" -ErrorAction SilentlyContinue | ForEach-Object {
            $fileRows += [pscustomobject]@{
                Path          = $_.FullName
                Extension     = $ext
                Length        = $_.Length
                LastWriteTime = $_.LastWriteTime
                Owner         = (Get-OwnerName $_.FullName)
            }
        }
    }
}
$fileRows = @($fileRows | Sort-Object Path -Unique)

Write-Host "[*] Recherche des references dans scripts/configs..."
$textExts = @('.ps1', '.psm1', '.psd1', '.cmd', '.bat', '.vbs', '.js', '.yml', '.yaml', '.json', '.xml', '.config', '.ini', '.env', '.sh')
$pattern = 'signtool|Set-AuthenticodeSignature|Import-PfxCertificate|AzureSignTool|trusted-signing|osslsigncode|jsign|importpfx|\.pfx|\.p12'
$scriptRows = @()
foreach ($root in $Roots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $textExts -contains $_.Extension.ToLower() -and $_.Length -lt 1MB } |
        ForEach-Object {
            $file = $_
            Select-String -Path $file.FullName -Pattern $pattern -ErrorAction SilentlyContinue | ForEach-Object {
                $line = ''
                if ($ShowMatchLines) { $line = Hide-Secrets $_.Line }
                $scriptRows += [pscustomobject]@{
                    Path       = $file.FullName
                    LineNumber = $_.LineNumber
                    Match      = $_.Matches[0].Value
                    Line       = $line
                }
            }
        }
}

Write-Host "[*] Recherche dans l'historique PowerShell..."
$histPaths = New-Object System.Collections.Generic.List[string]
$histPaths.Add("$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
if (Test-Path 'C:\Users') {
    Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        $histPaths.Add($p)
    }
}
$histRows = @()
foreach ($hp in ($histPaths | Sort-Object -Unique)) {
    if (Test-Path $hp) {
        Select-String -Path $hp -Pattern $pattern -ErrorAction SilentlyContinue | ForEach-Object {
            $line = ''
            if ($ShowMatchLines) { $line = Hide-Secrets $_.Line }
            $histRows += [pscustomobject]@{
                Path       = $hp
                LineNumber = $_.LineNumber
                Match      = $_.Matches[0].Value
                Line       = $line
            }
        }
    }
}

Write-Host "[*] Detection des outils de signature..."
$toolRows = @()
foreach ($name in @('signtool.exe', 'signtool', 'osslsigncode.exe', 'AzureSignTool.exe', 'AzureSignTool', 'jsign.jar', 'jsign', 'trusted-signing-cli.exe')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) {
        $toolRows += [pscustomobject]@{ Tool = $name; Source = $cmd.Source; Kind = 'PATH' }
    }
}
foreach ($kit in @('C:\Program Files (x86)\Windows Kits\10\bin', 'C:\Program Files\Windows Kits\10\bin')) {
    if (Test-Path $kit) {
        Get-ChildItem $kit -Recurse -Filter 'signtool.exe' -File -ErrorAction SilentlyContinue | ForEach-Object {
            $toolRows += [pscustomobject]@{ Tool = 'signtool.exe'; Source = $_.FullName; Kind = 'WindowsKits' }
        }
    }
}
$toolRows = @($toolRows | Sort-Object Source -Unique)

$eventRows = @()
if ($IncludeEvents) {
    Write-Host "[*] Recherche des evenements recents..."
    $start = (Get-Date).AddDays(-30)
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $start } -MaxEvents 20000 -ErrorAction Stop |
            Where-Object { $_.Message -match 'signtool|AzureSignTool|osslsigncode|jsign|certutil.*importpfx' } |
            ForEach-Object {
                $eventRows += [pscustomobject]@{
                    TimeCreated = $_.TimeCreated
                    Source      = 'Security 4688'
                    Id          = $_.Id
                    Summary     = (((($_.Message -split "\r?\n") | Where-Object { $_ -match 'signtool|AzureSignTool|osslsigncode|jsign|certutil' }) | Select-Object -First 2) -join ' | ')
                }
            }
    } catch { Write-Warning "Evenements 4688 indisponibles: $($_.Exception.Message)" }

    try {
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20000 -ErrorAction Stop |
            Where-Object { $_.Id -eq 1 -and $_.Message -match 'signtool|AzureSignTool|osslsigncode|jsign|certutil.*importpfx' } |
            ForEach-Object {
                $eventRows += [pscustomobject]@{
                    TimeCreated = $_.TimeCreated
                    Source      = 'Sysmon 1'
                    Id          = $_.Id
                    Summary     = (((($_.Message -split "\r?\n") | Where-Object { $_ -match 'signtool|AzureSignTool|osslsigncode|jsign|certutil' }) | Select-Object -First 2) -join ' | ')
                }
            }
    } catch { Write-Warning "Sysmon indisponible: $($_.Exception.Message)" }
}

Write-Host "[*] Ecriture du rapport..."
if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

function Export-RowSet {
    param($Data, [string]$Name)
    if ($Data -and @($Data).Count -gt 0) {
        $Data | Export-Csv -Path (Join-Path $OutDir $Name) -NoTypeInformation -Encoding UTF8
    }
}

Export-RowSet $certRows 'certificates.csv'
Export-RowSet $keyRows 'key_containers.csv'
Export-RowSet $fileRows 'candidate_files.csv'
Export-RowSet $scriptRows 'script_references.csv'
Export-RowSet $histRows 'history_references.csv'
Export-RowSet $toolRows 'signing_tools.csv'
if ($IncludeEvents) { Export-RowSet $eventRows 'signing_events.csv' }

$summary = [pscustomobject]@{
    Timestamp         = (Get-Date).ToString('o')
    Computer          = $env:COMPUTERNAME
    User              = "$env:USERDOMAIN\$env:USERNAME"
    Roots             = ($Roots -join '; ')
    Certificates      = @($certRows).Count
    CertsWithKey      = @($certRows | Where-Object { $_.HasPrivateKey }).Count
    KeyContainers     = @($keyRows).Count
    CandidateFiles    = @($fileRows).Count
    ScriptReferences  = @($scriptRows).Count
    HistoryReferences = @($histRows).Count
    SigningTools      = @($toolRows).Count
    Events            = @($eventRows).Count
}
$summary | ConvertTo-Json | Set-Content -Path (Join-Path $OutDir 'summary.json') -Encoding UTF8

Write-Host ""
Write-Host "== Resume =="
Write-Host ("Certificats: {0} (avec cle privee: {1})" -f $summary.Certificates, $summary.CertsWithKey)
Write-Host ("Fichiers candidats: {0}" -f $summary.CandidateFiles)
Write-Host ("References scripts/historique: {0}/{1}" -f $summary.ScriptReferences, $summary.HistoryReferences)
Write-Host ("Rapport: {0}" -f $OutDir)

$withKey = @($certRows | Where-Object { $_.HasPrivateKey })
if ($withKey.Count -gt 0) {
    Write-Host ""
    Write-Host "== Certificats avec cle privee =="
    $withKey | Format-Table Subject, Thumbprint, NotAfter, CodeSigningEku, Store -AutoSize | Out-String | Write-Host
}

$recentFiles = @($fileRows | Sort-Object LastWriteTime -Descending | Select-Object -First 20)
if ($recentFiles.Count -gt 0) {
    Write-Host "== Derniers fichiers candidats =="
    $recentFiles | Format-Table Path, Length, LastWriteTime -AutoSize | Out-String | Write-Host
}

Write-Host "Rapport potentiellement sensible (chemins, empreintes, utilisateurs). Protege-le."
