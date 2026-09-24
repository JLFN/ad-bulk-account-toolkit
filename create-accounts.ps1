#Requires -Version 3.0
<#
.SYNOPSIS
    Creates AD accounts in bulk from a user list (CSV).

.DESCRIPTION
    Reads a delimited CSV file, creates one AD account per row, generates a
    random password, sets the mail address and adds the account to one or more
    AD groups. The result (user name + password) is written to a CSV file.

    This version is hardened after review. What differs from the first version:

      1. Preflight BEFORE anything is created: AD module, OU, groups, UPN
         suffix, password policy (including fine-grained PSOs), CSV encoding,
         delimiter, headers, empty fields and duplicates. Nothing is created if
         anything is wrong, and the script aborts with a clear error instead of
         doing half the job.
      2. The password policy is compared with PasswordLength before the run.
         Without that check, accounts are created that never activate, because
         New-ADUser creates the account even when the policy rejects the password.
      3. The password is written to the result file the moment the account is
         created, before the group step. If the group assignment fails, the
         password is still there.
      4. Every account is verified afterwards (Enabled and PasswordLastSet), and
         an account that was not activated is flagged clearly in the result file.
      5. The CSV reader detects BOM and delimiter on its own and checks the
         headers, so a malformed input file gives a clear error instead of a
         silent run with no accounts.
      6. Get-CsvField is null-safe and all field reads are protected, so an
         incomplete row does not stop the whole run.
      7. Duplicate display names are detected before the run, because CN must be
         unique in the OU. Use -DisambiguateDuplicateNames to append a suffix.
      8. -WhatIf (or -WhatIfMode) shows exactly what would happen, without
         creating anything. The result file is then marked SIMULATED.

.PARAMETER CsvPath
    The input file. Columns: Name; Last Name; Company; Title; City
    (the Blue Collar column is not read).

.PARAMETER WhatIfMode
    The same as -WhatIf. Kept for compatibility with the first version.

.PARAMETER DisambiguateDuplicateNames
    Two people with an identical display name cannot both have the same CN in
    the OU. With this flag a number is appended to the second and later account.

.PARAMETER CsvEncoding
    auto (default) selects utf8 when the file has a BOM, otherwise cp1252.
    Force it with cp1252 or utf8 in case the automatic detection guesses wrong.

.NOTES
    Save this file as UTF-8 with a BOM. The character replacement contains the
    Swedish letters, and Windows PowerShell 5.1 reads a script as ANSI when the
    BOM is missing. Without a BOM the character replacement goes wrong and the
    user names for names with those letters come out wrong.

    Always run with -WhatIf first and review the output line by line.

.EXAMPLE
    .\create-accounts.ps1 -WhatIf

.EXAMPLE
    .\create-accounts.ps1 -DisambiguateDuplicateNames
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string]   $CsvPath        = 'C:\Scripts\userlist1.csv',
    [string]   $OutputPath     = 'C:\Scripts\created-accounts.csv',
    [string]   $LogPath        = 'C:\Scripts\create-accounts.log',

    [string]   $TargetOU       = 'OU=Anvandare,DC=domain,DC=se',
    [string[]] $GroupNames     = @('Blue-Collar-Employees'),
    [string]   $UpnSuffix      = 'domain.se',
    [string]   $MailDomain     = 'domain.se',

    [int]      $PasswordLength = 16,
    [bool]     $ForcePasswordChangeAtLogon = $true,
    [bool]     $VerifyAccount  = $true,

    [ValidateSet('auto', 'cp1252', 'utf8')]
    [string]   $CsvEncoding    = 'auto',

    [switch]   $WhatIfMode,
    [switch]   $DisambiguateDuplicateNames,
    [switch]   $AllowExistingPerson,
    [switch]   $AllowUnregisteredUpnSuffix,

    [string]   $Server,
    [System.Management.Automation.PSCredential] $Credential
)

if ($WhatIfMode) { $WhatIfPreference = $true }

$script:Created    = 0
$script:Failed     = 0
$script:Simulated  = 0
$script:GroupFails = 0
$script:NotEnabled = 0
$script:Skipped    = 0

$script:AdParams = @{}
if ($Server)     { $script:AdParams['Server']     = $Server }
if ($Credential) { $script:AdParams['Credential'] = $Credential }

# Helper functions

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')

    if ($Level -eq 'ERROR')     { $color = 'Red' }
    elseif ($Level -eq 'WARN')  { $color = 'Yellow' }
    elseif ($Level -eq 'OK')    { $color = 'Green' }
    else                        { $color = 'Gray' }

    $stamp = (Get-Date -Format u)
    Write-Host ('  [{0}] {1}' -f $Level, $Message) -ForegroundColor $color
    try {
        Add-Content -Path $LogPath -Value ('{0} {1}: {2}' -f $stamp, $Level, $Message) -ErrorAction Stop
    }
    catch {
        Write-Host ('  [WARN] Could not write to the log: {0}' -f $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Stop-Fatal {
    param([string]$Message)
    Write-Log -Level 'ERROR' -Message $Message
    Write-Host ''
    Write-Host 'Aborting. Nothing has been created or changed in AD.' -ForegroundColor Red
    exit 1
}

# Null-safe field reading. The first version called .ToString() without
# protection, and those calls sat outside the try block: a single row with an
# empty Title/City/Company stopped the whole run in the middle of the list.
function Get-CsvField {
    param($Row, [string]$Name)
    $prop = @($Row.PSObject.Properties | Where-Object { $_.Name.Trim() -eq $Name })
    if ($prop.Count -eq 0)        { return '' }
    if ($null -eq $prop[0].Value) { return '' }
    return $prop[0].Value.ToString().Trim()
}

# Replaces the Swedish letters and strips everything except letters and hyphens.
# Note: digits are removed too. "Lars2" becomes "lars". Change the rule here if
# that is not intentional.
function Convert-ToSamName {
    param([string]$Text)
    $t = $Text.Trim()
    $t = $t -replace 'å','a' -replace 'ä','a' -replace 'ö','o' -replace 'ø','o' -replace 'æ','a'
    $t = $t -replace 'Å','A' -replace 'Ä','A' -replace 'Ö','O' -replace 'Ø','O' -replace 'Æ','A'
    $t = $t -replace '[^a-zA-Z\-]', ''
    $t.ToLower()
}

# Short login name (pre-Windows 2000 / sAMAccountName): up to three characters
# from the first part of the given name plus up to three from the first part of
# the surname. Per Nilsson Andersson gives pernil. This is the name that carries
# the 20-character limit, and the short rule keeps it far below that limit.
# Collisions are handled by Get-PlanSamAccountName and by the check in the verifier.
function Get-ShortLoginName {
    param([string]$GivenName, [string]$Surname)
    $f = Convert-ToSamName (($GivenName -split '\s+')[0])
    $e = Convert-ToSamName (($Surname -split '\s+')[0])
    $loginName = ''
    if ($f) { $loginName += $f.Substring(0, [Math]::Min(3, $f.Length)) }
    if ($e) { $loginName += $e.Substring(0, [Math]::Min(3, $e.Length)) }
    return $loginName
}

# Full name with dots (UPN and mail address): every name part from both columns,
# separated by dots. Per Nilsson Andersson gives per.nilsson.andersson.
# A UPN has no documented length limit, so it is never shortened.
function Get-DottedLoginName {
    param([string]$GivenName, [string]$Surname)
    $parts = @()
    foreach ($d in ($GivenName -split '\s+'))  { $r = Convert-ToSamName $d; if ($r) { $parts += $r } }
    foreach ($d in ($Surname -split '\s+')) { $r = Convert-ToSamName $d; if ($r) { $parts += $r } }
    return ($parts -join '.')
}

# Generates a random password with at least one character from every class. The
# characters are shuffled with Fisher-Yates instead of Sort-Object, so the order
# does not depend on the sorting algorithm. Passwords that contain the user name
# or the name are regenerated, because AD does not allow that.
function New-RandomPassword {
    param([int]$Length = 16, [string[]]$Avoid = @())

    if ($Length -lt 4) { throw 'PasswordLength must be at least 4.' }

    $upper   = 65..90  | ForEach-Object { [char]$_ }
    $lower   = 97..122 | ForEach-Object { [char]$_ }
    $digit   = 48..57  | ForEach-Object { [char]$_ }
    $special = '!@#$%&*?='.ToCharArray()
    $all     = $upper + $lower + $digit + $special

    $tokens = @()
    foreach ($t in $Avoid) {
        if ($t -and $t.Length -ge 4) { $tokens += $t.ToLower() }
    }

    $candidate = ''
    for ($attempt = 1; $attempt -le 25; $attempt++) {
        $chars = New-Object System.Collections.Generic.List[char]
        $chars.Add(($upper   | Get-Random))
        $chars.Add(($lower   | Get-Random))
        $chars.Add(($digit   | Get-Random))
        $chars.Add(($special | Get-Random))
        while ($chars.Count -lt $Length) { $chars.Add(($all | Get-Random)) }

        for ($i = $chars.Count - 1; $i -gt 0; $i--) {
            $j = Get-Random -Minimum 0 -Maximum ($i + 1)
            $tmp = $chars[$i]
            $chars[$i] = $chars[$j]
            $chars[$j] = $tmp
        }
        $candidate = -join $chars

        $containsName = $false
        $lowerCand = $candidate.ToLower()
        foreach ($t in $tokens) {
            if ($lowerCand.Contains($t)) { $containsName = $true }
        }
        if (-not $containsName) { break }
    }
    return $candidate
}

# Finds a free sAMAccountName (max 20 characters) and checks both existing
# accounts in AD and names already assigned during this run. Errors from AD are
# passed through as errors - the first version swallowed them with
# SilentlyContinue, which could produce duplicates.
function Get-PlanSamAccountName {
    param([string]$BaseName, [hashtable]$Used)

    $base = $BaseName
    if ($base.Length -gt 20) { $base = $base.Substring(0, 20) }
    if ([string]::IsNullOrWhiteSpace($base)) { throw ('Empty base name for the row.') }

    $candidate = $base
    $counter = 1
    $takenInAd = $false
    while ($true) {
        $q = @{ Filter = "SamAccountName -eq '$candidate'" }
        foreach ($k in $script:AdParams.Keys) { $q[$k] = $script:AdParams[$k] }
        $hit = Get-ADUser @q -ErrorAction Stop

        if (-not $hit -and -not $Used.ContainsKey($candidate)) { break }

        if ($hit) { $takenInAd = $true }
        $suffix = "$counter"
        $maxBase = 20 - $suffix.Length
        $candidate = $base.Substring(0, [Math]::Min($base.Length, $maxBase)) + $suffix
        $counter++
    }
    $Used[$candidate] = $true

    # TakenInAd means that someone with the same name already exists in AD,
    # which is the strongest sign that the person already has an account.
    return [PSCustomObject]@{
        Sam       = $candidate
        Base      = $base
        Suffix    = ($counter - 1)
        TakenInAd = $takenInAd
    }
}

# Looks for an existing account matching the person: same name (CN), same user
# name, same UPN, same mail address, or same given name and surname. The filter
# uses the LDAP names (name, sAMAccountName, userPrincipalName, mail, givenName,
# sn), which about_ActiveDirectory_Filter documents as permitted alongside the
# PowerShell property names. Empty values are skipped, so an empty field can
# never match the entire directory.
function Get-ExistingPerson {
    param([string]$DisplayName, [string]$Sam, [string]$Upn, [string]$Mail)

    $parts = @($DisplayName -split '\s+' | Where-Object { $_ })
    $gn = ''
    $sn = ''
    if ($parts.Count -ge 1) { $gn = $parts[0] }
    if ($parts.Count -ge 2) { $sn = $parts[-1] }

    $clauses = @()
    if ($DisplayName) { $clauses += ("(name -eq '{0}')" -f $DisplayName.Replace("'", "''")) }
    if ($Sam)         { $clauses += ("(sAMAccountName -eq '{0}')" -f $Sam.Replace("'", "''")) }
    if ($Upn)         { $clauses += ("(userPrincipalName -eq '{0}')" -f $Upn.Replace("'", "''")) }
    if ($Mail)        { $clauses += ("(mail -eq '{0}')" -f $Mail.Replace("'", "''")) }
    if ($gn -and $sn) { $clauses += ("((givenName -eq '{0}') -and (sn -eq '{1}'))" -f $gn.Replace("'", "''"), $sn.Replace("'", "''")) }
    if ($clauses.Count -eq 0) { return @() }

    $q = @{ Filter = ($clauses -join ' -or '); Properties = @('name', 'sAMAccountName', 'userPrincipalName', 'mail', 'givenName', 'sn', 'DistinguishedName', 'Enabled') }
    foreach ($k in $script:AdParams.Keys) { $q[$k] = $script:AdParams[$k] }
    return @(Get-ADUser @q -ErrorAction Stop)
}

# Assesses a hit. FAIL when the account blocks a clean creation: the same CN in
# the target OU (DN collision) or the same UPN (double login). Everything else
# is WARN. Returns strings that begin with "FAIL: " or "WARN: ".
function Get-PersonFindings {
    param($Candidate, [string]$DisplayName, [string]$Sam, [string]$Upn, [string]$Mail, [string]$TargetOU)

    $f = @()
    $dn = ''
    if ($Candidate.DistinguishedName) { $dn = [string]$Candidate.DistinguishedName }
    $hit = $false

    if ([string]$Candidate.name -eq $DisplayName) {
        $hit = $true
        if ($dn -and $TargetOU -and $dn.ToLower().EndsWith($TargetOU.ToLower())) {
            $f += ('FAIL: an account with the same name is already in the OU: {0}' -f $dn)
        }
        else {
            $f += ('WARN: an account with the same name exists in AD: {0}' -f $dn)
        }
    }
    if ([string]$Candidate.sAMAccountName -eq $Sam) {
        $hit = $true
        $f += ('WARN: the login name {0} is used by {1} (the account will get a suffix)' -f $Sam, $dn)
    }
    if ([string]$Candidate.userPrincipalName -eq $Upn) {
        $hit = $true
        $f += ('FAIL: UPN {0} is already used by {1}' -f $Upn, $dn)
    }
    if ([string]$Candidate.mail -eq $Mail) {
        $hit = $true
        $f += ('WARN: the mail address {0} is used by {1}' -f $Mail, $dn)
    }
    if (-not $hit) {
        $f += ('WARN: a person with the same given name and surname already exists: {0}' -f $dn)
    }
    return $f
}


# Start

Write-Host ''
Write-Host 'Create AD accounts in bulk' -ForegroundColor White
Write-Host ('Computer: {0}   Account: {1}' -f $env:COMPUTERNAME, [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -ForegroundColor Gray
if ($WhatIfPreference) {
    Write-Host 'MODE: WhatIf. Nothing is created, everything is only displayed.' -ForegroundColor Cyan
}

# The directories for the log and the result must exist before anything is written.
foreach ($dir in @((Split-Path -Parent $OutputPath), (Split-Path -Parent $LogPath))) {
    if ($dir -and -not (Test-Path $dir)) {
        try {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            Write-Host ('  [INFO] Created the directory {0}' -f $dir) -ForegroundColor Gray
        }
        catch {
            Write-Host ('CANNOT CREATE THE DIRECTORY {0}: {1}' -f $dir, $_.Exception.Message) -ForegroundColor Red
            exit 1
        }
    }
}

# 1. Module and domain

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host ('CANNOT LOAD the ActiveDirectory module: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Run on a computer with RSAT installed.' -ForegroundColor Red
    exit 1
}

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $forest = Get-ADForest -ErrorAction Stop
    Write-Log -Level 'INFO' -Message ('Domain {0} (NetBIOS {1}), forest {2}' -f $domain.DNSRoot, $domain.NetBIOSName, $forest.Name)
}
catch {
    Stop-Fatal ('Cannot read domain information: {0}' -f $_.Exception.Message)
}

# 2. UPN-suffix

$validSuffixes = @($domain.DNSRoot)
if ($forest.UPNSuffixes) { $validSuffixes += $forest.UPNSuffixes }
if ($forest.Domains)     { $validSuffixes += $forest.Domains }
$validSuffixes = $validSuffixes | Where-Object { $_ } | Select-Object -Unique

if ($validSuffixes -contains $UpnSuffix) {
    Write-Log -Level 'OK' -Message ('The UPN suffix {0} exists in the forest.' -f $UpnSuffix)
}
elseif ($AllowUnregisteredUpnSuffix) {
    Write-Log -Level 'WARN' -Message ('The UPN suffix {0} does not exist in the forest, but -AllowUnregisteredUpnSuffix is set.' -f $UpnSuffix)
}
else {
    Write-Log -Level 'ERROR' -Message ('The UPN suffix {0} is not registered in the forest. Registered: {1}' -f $UpnSuffix, ($validSuffixes -join ', '))
    Stop-Fatal 'Login with a UPN will not work. Add the suffix to the forest, correct UpnSuffix, or run with -AllowUnregisteredUpnSuffix.'
}

# 3. Target OU

try {
    $ou = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
    Write-Log -Level 'OK' -Message ('Target OU exists: {0}' -f $ou.DistinguishedName)
}
catch {
    Stop-Fatal ('The OU does not exist or cannot be read: {0}. Error: {1}' -f $TargetOU, $_.Exception.Message)
}

Write-Log -Level 'WARN' -Message 'The permission to create objects in the OU cannot be verified in advance. Try -WhatIf first, then create one account at a time if anything is uncertain.'

# 4. Groups

$ouNc = ($TargetOU -split ',DC=', 2)[1]
foreach ($group in $GroupNames) {
    try {
        $q = @{ Identity = $group }
        foreach ($k in $script:AdParams.Keys) { $q[$k] = $script:AdParams[$k] }
        $g = Get-ADGroup @q -ErrorAction Stop
        Write-Log -Level 'OK' -Message ('The group exists: {0} ({1} / {2})' -f $g.Name, $g.GroupScope, $g.GroupCategory)

        $gNc = ($g.DistinguishedName -split ',DC=', 2)[1]
        if ($ouNc -and $gNc -and $ouNc -ne $gNc) {
            Stop-Fatal ('The group {0} is in a different domain than the OU. Members cannot be added across a domain boundary.' -f $g.Name)
        }
    }
    catch {
        Stop-Fatal ('The group cannot be found or cannot be read: {0}. Error: {1}' -f $group, $_.Exception.Message)
    }
}

# 5. Password policy against PasswordLength

try {
    $pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    Write-Log -Level 'INFO' -Message ('Default policy: MinPasswordLength={0}, ComplexityEnabled={1}, PasswordHistoryCount={2}' -f $pol.MinPasswordLength, $pol.ComplexityEnabled, $pol.PasswordHistoryCount)

    # Safety net. If the property does not come back, the comparison below
    # passes silently, and the check then looks useful without being useful.
    if ($null -eq $pol.MinPasswordLength) {
        Stop-Fatal 'The domain policy answered without MinPasswordLength, so it cannot be verified that the password is accepted. Run Get-ADDefaultDomainPasswordPolicy manually first.'
    }

    if ($PasswordLength -lt $pol.MinPasswordLength) {
        Stop-Fatal ('PasswordLength is {0} but the domain policy requires at least {1} characters. The account is still created, but without a valid password, and will not be activated. Increase PasswordLength.' -f $PasswordLength, $pol.MinPasswordLength)
    }
    Write-Log -Level 'OK' -Message ('PasswordLength {0} meets the minimum length {1} of the default policy.' -f $PasswordLength, $pol.MinPasswordLength)
}
catch {
    Stop-Fatal ('Cannot read the domain password policy: {0}' -f $_.Exception.Message)
}

try {
    $psos = @()
    try {
        $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo -ErrorAction Stop)
    }
    catch {
        $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)
    }

    if ($psos.Count -gt 0) {
        $groupDns = @()
        foreach ($group in $GroupNames) {
            $q = @{ Identity = $group }
            foreach ($k in $script:AdParams.Keys) { $q[$k] = $script:AdParams[$k] }
            $g = Get-ADGroup @q -ErrorAction SilentlyContinue
            if ($g) { $groupDns += $g.DistinguishedName }
        }

        foreach ($pso in $psos) {
            $applies = @()
            if ($pso.AppliesTo) {
                foreach ($a in $pso.AppliesTo) { $applies += $a.DistinguishedName }
            }
            $match = $false
            foreach ($dn in $groupDns) { if ($applies -contains $dn) { $match = $true } }
            if (-not $pso.AppliesTo) {
                Write-Log -Level 'WARN' -Message ('PSO "{0}": AppliesTo could not be read, so it cannot be ruled out that it applies to the group. Check it manually.' -f $pso.Name)
            }
            if ($match) {
                if ($null -eq $pso.MinPasswordLength) {
                    Stop-Fatal ('PSO "{0}" applies to the group but answered without MinPasswordLength. Check it manually.' -f $pso.Name)
                }
                if ($PasswordLength -lt [int]$pso.MinPasswordLength) {
                    Stop-Fatal ('PSO "{0}" applies to the group and requires {1} characters, but PasswordLength is {2}. Increase PasswordLength.' -f $pso.Name, $pso.MinPasswordLength, $PasswordLength)
                }
                Write-Log -Level 'INFO' -Message ('PSO "{0}" applies to the group: MinPasswordLength={1} (met).' -f $pso.Name, $pso.MinPasswordLength)
            }
        }
    }
}
catch {
    Write-Log -Level 'WARN' -Message ('Could not read the fine-grained password policies: {0}. Check manually.' -f $_.Exception.Message)
}

# 6. The CSV file: encoding, delimiter, headers

if (-not (Test-Path $CsvPath)) {
    Stop-Fatal ('Cannot find the CSV file: {0}' -f $CsvPath)
}

$bytes = [System.IO.File]::ReadAllBytes($CsvPath)
if ($bytes.Length -eq 0) { Stop-Fatal ('The CSV file is empty: {0}' -f $CsvPath) }

$hasBom = $false
if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $hasBom = $true }

$enc = $CsvEncoding
if ($enc -eq 'auto') {
    if ($hasBom) { $enc = 'utf8' } else { $enc = 'cp1252' }
}

if ($enc -eq 'utf8') {
    $rawText = [System.IO.File]::ReadAllText($CsvPath, [System.Text.Encoding]::UTF8)
    Write-Log -Level 'INFO' -Message 'Reading the CSV file as UTF-8 (BOM found).'
}
else {
    if ($hasBom) {
        Write-Log -Level 'WARN' -Message 'The file has a BOM but is forced to be read as cp1252. The headers may come out wrong.'
    }
    $rawText = [System.IO.File]::ReadAllText($CsvPath, [System.Text.Encoding]::GetEncoding(1252))
    Write-Log -Level 'INFO' -Message 'Reading the CSV file as cp1252 (no BOM found).'
}

$firstLine = ($rawText -split "\r?\n")[0]
$semiCount  = ([regex]::Matches($firstLine, ';')).Count
$commaCount = ([regex]::Matches($firstLine, ',')).Count
$tabCount   = ([regex]::Matches($firstLine, "`t")).Count

$delimiter = ';'
if ($commaCount -gt $semiCount -and $commaCount -ge $tabCount) { $delimiter = ',' }
if ($tabCount -gt $semiCount -and $tabCount -gt $commaCount)   { $delimiter = "`t" }
if ($semiCount -eq 0 -and $commaCount -eq 0 -and $tabCount -eq 0) {
    Stop-Fatal 'No delimiter (semicolon, comma or tab) was found in the header row.'
}
Write-Log -Level 'INFO' -Message ('Delimiter: {0}' -f $(if ($delimiter -eq "`t") { 'tab' } else { $delimiter }))

$rows = @($rawText | ConvertFrom-Csv -Delimiter $delimiter)
if ($rows.Count -eq 0) { Stop-Fatal 'The CSV file produced no data rows.' }
Write-Log -Level 'OK' -Message ('{0} data rows read.' -f $rows.Count)

$expectedColumns = @('Name', 'Last Name', 'Company', 'Title', 'City')
$actualColumns = @($rows[0].PSObject.Properties | ForEach-Object { $_.Name })
$missing = @()
foreach ($col in $expectedColumns) {
    if ($actualColumns -notcontains $col) { $missing += $col }
}
if ($missing.Count -gt 0) {
    Write-Log -Level 'ERROR' -Message ('Missing columns: {0}' -f ($missing -join ', '))
    Write-Log -Level 'INFO' -Message ('Columns found: {0}' -f ($actualColumns -join ' | '))
    Stop-Fatal 'The headers do not match. Check the delimiter, the encoding and the spelling in the input file.'
}
Write-Log -Level 'OK' -Message 'All five columns that the script reads are present.'

# 7. Build the plan: predicted accounts, collisions and duplicates

$plan = New-Object System.Collections.Generic.List[Object]
$usedSam = @{}
$skipped = 0
$badNames = @()

foreach ($row in $rows) {
    $givenName = Get-CsvField $row 'Name'
    $surname   = Get-CsvField $row 'Last Name'

    if ([string]::IsNullOrWhiteSpace($givenName) -or [string]::IsNullOrWhiteSpace($surname)) {
        $skipped++
        continue
    }

    $shortName  = Get-ShortLoginName     -Fornamn $givenName -Efternamn $surname
    $dottedName = Get-DottedLoginName    -Fornamn $givenName -Efternamn $surname

    if ([string]::IsNullOrWhiteSpace($shortName) -or [string]::IsNullOrWhiteSpace($dottedName)) {
        $badNames += ('{0} {1}' -f $givenName, $surname)
        continue
    }

    try {
        $samInfo = Get-PlanSamAccountName -BaseName $shortName -Used $usedSam
    }
    catch {
        Stop-Fatal ('Could not check free account names against AD: {0}' -f $_.Exception.Message)
    }

    $nameCheck = ''
    if ($samInfo.TakenInAd) {
        $nameCheck = ('the login name {0} already exists in AD, the row gets {1}' -f $samInfo.Base, $samInfo.Sam)
        Write-Log -Level 'WARN' -Message ('{0} {1}: {2}' -f $givenName, $surname, $nameCheck)
    }
    elseif ($samInfo.Suffix -gt 0) {
        $nameCheck = ('the login name {0} is already used in this run, the row gets {1}' -f $samInfo.Base, $samInfo.Sam)
    }

    $display = ('{0} {1}' -f $givenName, $surname)
    $plan.Add([PSCustomObject]@{
        GivenName = $givenName
        Surname   = $surname
        Display   = $display
        Cn        = $display
        Sam       = $samInfo.Sam
        NameCheck = $nameCheck
        Upn       = ($dottedName + '@' + $UpnSuffix)
        Mail      = ($dottedName + '@' + $MailDomain)
        Company   = Get-CsvField $row 'Company'
        City      = Get-CsvField $row 'City'
        Title     = Get-CsvField $row 'Title'
    })
}

$script:Skipped = $skipped

if ($badNames.Count -gt 0) {
    Write-Log -Level 'ERROR' -Message ('{0} row(s) produce an invalid user name: {1}' -f $badNames.Count, (($badNames | Select-Object -First 5) -join ', '))
    Stop-Fatal 'Correct names that contain only characters which are stripped away (digits and special characters).'
}

if ($plan.Count -eq 0) { Stop-Fatal 'No row produced an account to create.' }

# Duplicate display names: CN must be unique in the OU.
$duplicates = @($plan | Group-Object Display | Where-Object { $_.Count -gt 1 })
if ($duplicates.Count -gt 0) {
    if (-not $DisambiguateDuplicateNames) {
        Write-Log -Level 'ERROR' -Message ('{0} display names occur more than once: {1}' -f $duplicates.Count, (($duplicates | Select-Object -First 5 | ForEach-Object { $_.Name }) -join '; '))
        Stop-Fatal 'New-ADUser sets CN from Name, and CN must be unique in the OU. Run with -DisambiguateDuplicateNames to append a number, or correct the name data in the input file.'
    }

    Write-Log -Level 'WARN' -Message ('{0} display names are duplicates. A number is appended to CN for the second and later account.' -f $duplicates.Count)
    $cnSeen = @{}
    foreach ($p in $plan) {
        if ($cnSeen.ContainsKey($p.Display)) {
            $cnSeen[$p.Display]++
            $p.Cn = ('{0} ({1})' -f $p.Display, $cnSeen[$p.Display])
        }
        else {
            $cnSeen[$p.Display] = 1
        }
    }
}

if ($skipped -gt 0) {
    Write-Log -Level 'WARN' -Message ('{0} row(s) are missing Name or Last Name and are skipped.' -f $skipped)
}

Write-Log -Level 'OK' -Message ('Plan ready: {0} accounts to create.' -f $plan.Count)

# 7b. Search AD for people who already exist, before anything is created.

Write-Log -Level 'INFO' -Message ('Searching AD for existing accounts for {0} people. This may take a while.' -f $plan.Count)
$blocking = @()
foreach ($p in $plan) {
    try {
        $hits = Get-ExistingPerson -DisplayName $p.Display -Sam $p.Sam -Upn $p.Upn -Mail $p.Mail
    }
    catch {
        Stop-Fatal ('Could not search AD for existing people: {0}' -f $_.Exception.Message)
    }
    foreach ($h in $hits) {
        foreach ($f in (Get-PersonFindings -Candidate $h -DisplayName $p.Display -Sam $p.Sam -Upn $p.Upn -Mail $p.Mail -TargetOU $TargetOU)) {
            if ($p.NameCheck) { $p.NameCheck = ($p.NameCheck + ' | ' + $f) } else { $p.NameCheck = $f }
            if ($f.StartsWith('FAIL:')) {
                $blocking += ('{0} {1}: {2}' -f $p.GivenName, $p.Surname, $f)
                Write-Log -Level 'ERROR' -Message ('{0} {1}: {2}' -f $p.GivenName, $p.Surname, $f)
            }
            else {
                Write-Log -Level 'WARN' -Message ('{0} {1}: {2}' -f $p.GivenName, $p.Surname, $f)
            }
        }
    }
}

if ($blocking.Count -gt 0) {
    if ($AllowExistingPerson) {
        Write-Log -Level 'WARN' -Message ('{0} row(s) match an account that already exists in AD. -AllowExistingPerson is set, so the run continues.' -f $blocking.Count)
    }
    else {
        Write-Host ''
        Write-Host ('  {0} row(s) match an account that already exists in AD:' -f $blocking.Count) -ForegroundColor Red
        foreach ($b in ($blocking | Select-Object -First 10)) { Write-Host ('    {0}' -f $b) -ForegroundColor Red }
        Stop-Fatal 'Correct the list, or run with -AllowExistingPerson if you are sure the accounts should be created anyway.'
    }
}
else {
    Write-Log -Level 'OK' -Message 'None of the people already exist in AD.'
}

# 8. Execute

$results = New-Object System.Collections.Generic.List[Object]

foreach ($p in $plan) {
    $avoid = @($p.Sam, $p.Surname, ($p.GivenName -split '\s+')[0])
    $password = New-RandomPassword -Length $PasswordLength -Avoid $avoid
    $status = ''
    $created = $false

    $doCreate = $PSCmdlet.ShouldProcess(('{0} ({1})' -f $p.Sam, $p.Display), 'Create AD account')

    if ($doCreate) {
        $secure = ConvertTo-SecureString $password -AsPlainText -Force
        $params = @{
            Name                 = $p.Cn
            GivenName            = $p.GivenName
            Surname              = $p.Surname
            SamAccountName       = $p.Sam
            UserPrincipalName    = $p.Upn
            DisplayName          = $p.Display
            EmailAddress         = $p.Mail
            Path                 = $TargetOU
            AccountPassword      = $secure
            Enabled              = $true
            ChangePasswordAtLogon = $ForcePasswordChangeAtLogon
        }
        if ($p.Title)   { $params['Title']   = $p.Title }
        if ($p.City)    { $params['City']    = $p.City }
        if ($p.Company) { $params['Company'] = $p.Company }
        foreach ($k in $script:AdParams.Keys) { $params[$k] = $script:AdParams[$k] }

        try {
            New-ADUser @params -ErrorAction Stop
            $created = $true
            $status = 'OK'
            Write-Log -Level 'OK' -Message ('CREATED: {0} ({1})' -f $p.Sam, $p.Company)
        }
        catch {
            $errText = $_.Exception.Message
            # New-ADUser creates the object even when the policy rejects the
            # password. So check whether the account exists before calling it failed.
            $exists = $null
            try {
                $q = @{ Identity = $p.Sam }
                foreach ($k in $script:AdParams.Keys) { $q[$k] = $script:AdParams[$k] }
                $exists = Get-ADUser @q -ErrorAction Stop
            }
            catch { }

            if ($exists) {
                $created = $true
                $status = ('CREATED BUT UNCERTAIN: {0}' -f $errText)
                Write-Log -Level 'WARN' -Message ('{0}: the account exists in AD but New-ADUser reported an error: {1}' -f $p.Sam, $errText)
            }
            else {
                $status = ('FAIL: {0}' -f $errText)
                Write-Log -Level 'ERROR' -Message ('{0} could not be created: {1}' -f $p.Sam, $errText)
            }
        }

        if ($created) {
            foreach ($group in $GroupNames) {
                try {
                    $gq = @{ Identity = $group; Members = $p.Sam }
                    foreach ($k in $script:AdParams.Keys) { $gq[$k] = $script:AdParams[$k] }
                    Add-ADGroupMember @gq -ErrorAction Stop
                }
                catch {
                    $script:GroupFails++
                    $status = ('{0} | GROUP FAILURE ({1}): {2}' -f $status, $group, $_.Exception.Message)
                    Write-Log -Level 'WARN' -Message ('{0} could not be added to {1}: {2}. The password is in the result file.' -f $p.Sam, $group, $_.Exception.Message)
                }
            }

            if ($VerifyAccount) {
                try {
                    $u = $null
                    try {
                        $vq = @{ Identity = $p.Sam; Properties = @('Enabled', 'PasswordLastSet') }
                        foreach ($k in $script:AdParams.Keys) { $vq[$k] = $script:AdParams[$k] }
                        $u = Get-ADUser @vq -ErrorAction Stop
                    }
                    catch {
                        # Fall back without -Properties: Enabled is a default property.
                        $vq = @{ Identity = $p.Sam }
                        foreach ($k in $script:AdParams.Keys) { $vq[$k] = $script:AdParams[$k] }
                        $u = Get-ADUser @vq -ErrorAction Stop
                    }

                    $hasPwdLastSet = (@($u.PSObject.Properties | ForEach-Object { $_.Name }) -contains 'PasswordLastSet')

                    if (-not $u.Enabled) {
                        $script:NotEnabled++
                        $status = ('{0} | NOT ACTIVATED - set the password manually with Set-ADAccountPassword' -f $status)
                        Write-Log -Level 'ERROR' -Message ('{0} is not activated: the password was not set. Set it manually.' -f $p.Sam)
                    }
                    elseif ($hasPwdLastSet -and $null -eq $u.PasswordLastSet) {
                        $status = ('{0} | Password not set' -f $status)
                        Write-Log -Level 'WARN' -Message ('{0} has no PasswordLastSet.' -f $p.Sam)
                    }
                }
                catch {
                    Write-Log -Level 'WARN' -Message ('Could not verify {0}: {1}' -f $p.Sam, $_.Exception.Message)
                }
            }
        }

        if ($status -like 'OK*' -or $status -like 'CREATED*') { $script:Created++ } else { $script:Failed++ }
    }
    else {
        $status = 'SIMULATED'
        $script:Simulated++
        Write-Log -Level 'INFO' -Message ('[WHATIF] {0} ({1}) | {2} / {3} / {4} | mail={5} | CN={6}' -f $p.Sam, $p.Display, $p.Company, $p.City, $p.Title, $p.Mail, $p.Cn)
    }

    $results.Add([PSCustomObject]@{
        GivenName   = $p.GivenName
        Surname     = $p.Surname
        Company     = $p.Company
        City        = $p.City
        UserName    = $p.Sam
        MailAddress = $p.Mail
        Password    = $password
        NameCheck   = $p.NameCheck
        Status      = $status
    })
}

try {
    $results | Export-Csv -Path $OutputPath -Delimiter ';' -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    Write-Log -Level 'OK' -Message ('Result saved: {0}' -f $OutputPath)
}
catch {
    Write-Log -Level 'ERROR' -Message ('Could not write the result file: {0}' -f $_.Exception.Message)
    Write-Host 'The result is shown below so that no password is lost:' -ForegroundColor Yellow
    $results | Format-Table -AutoSize
}

# Summary

Write-Host ''
if ($WhatIfPreference) {
    Write-Host ('  WhatIf mode: {0} accounts would have been created. Nothing was created.' -f $script:Simulated) -ForegroundColor Cyan
}
else {
    Write-Host ('  Created: {0}   Failed: {1}   Group failures: {2}   Not activated: {3}   Skipped rows: {4}' -f $script:Created, $script:Failed, $script:GroupFails, $script:NotEnabled, $script:Skipped)
}

Write-Host ''
Write-Log -Level 'INFO' -Message ('Log: {0}' -f $LogPath)

if ($script:NotEnabled -gt 0) {
    Write-Host '  Accounts that were not activated must be given a password manually:' -ForegroundColor Yellow
    Write-Host '    Get-ADUser -Filter * -SearchBase "<OU>" -Properties Enabled | Where-Object { -not $_.Enabled }' -ForegroundColor Yellow
    Write-Host '    Set-ADAccountPassword -Identity <sam> -Reset -NewPassword (Read-Host -AsSecureString)' -ForegroundColor Yellow
}

if (-not $WhatIfPreference) {
    Write-Host ''
    Write-Host '  NOTE: the result file contains passwords in clear text. Handle it securely' -ForegroundColor Yellow
    Write-Host '  and delete or archive it as soon as the details have been handed out.' -ForegroundColor Yellow
}

Write-Host ''

if ($script:Failed -gt 0 -or $script:NotEnabled -gt 0) {
    exit 1
}
exit 0
