#Requires -Version 3.0
<#
.SYNOPSIS
    Read-only pre-flight check for the bulk script that creates AD accounts (create-accounts.ps1).

.DESCRIPTION
    Checks everything that must be correct before create-accounts.ps1 runs against
    production: the AD module and the domain, the UPN suffix, the target OU,
    groups, the password policy (including fine-grained password policies), the
    encoding of the main script, and the CSV file's encoding, delimiter, headers,
    content, empty fields, duplicates and name collisions with existing accounts in AD.

    Every check is reported as OK, WARN or FAIL. At the end everything is summarized,
    and the script exits with code 1 if anything FAILED.

    The script is READ-ONLY. It creates, changes or deletes nothing in AD and writes
    no files.

.NOTES
    Run on a machine with RSAT (the ActiveDirectory module) and with the same account
    that will run create-accounts.ps1, so that the permissions are identical.

    Two things CANNOT be verified read-only and must be tried in a live run:
    whether the account may create objects in the OU, and whether the domain's
    password policy accepts the generated password.

.EXAMPLE
    .\Test-ADBulkReadiness.ps1

.EXAMPLE
    .\Test-ADBulkReadiness.ps1 -CsvPath C:\Scripts\userlist1.csv -ExpectedRows 260
#>

[CmdletBinding()]
param(
    [string]   $CsvPath        = 'C:\Scripts\userlist1.csv',
    [string]   $MainScriptPath = 'C:\Scripts\create-accounts.ps1',
    [string]   $TargetOU       = 'OU=Anvandare,DC=domain,DC=se',
    [string[]] $GroupNames     = @('Blue-Collar-Employees'),
    [string]   $UpnSuffix      = 'domain.se',
    [string]   $MailDomain     = 'domain.se',
    [int]      $PasswordLength = 16,
    [int]      $ExpectedRows   = 0
)

$script:Total = 0
$script:Fails = 0
$script:Warns = 0

function Add-Result {
    param([string]$Status, [string]$Message)
    $script:Total++
    if ($Status -eq 'FAIL') { $script:Fails++ ; $color = 'Red'    }
    elseif ($Status -eq 'WARN') { $script:Warns++ ; $color = 'Yellow' }
    elseif ($Status -eq 'OK')   { $color = 'Green' }
    else { $color = 'Gray' }
    Write-Host ('  [{0}] {1}' -f $Status, $Message) -ForegroundColor $color
}
function Add-Ok    { param([string]$m) Add-Result 'OK'   $m }
function Add-Fail  { param([string]$m) Add-Result 'FAIL' $m }
function Add-Warn  { param([string]$m) Add-Result 'WARN' $m }
function Add-Info  { param([string]$m) Write-Host ('         {0}' -f $m) -ForegroundColor Gray }
function Add-Head  { param([string]$m) Write-Host ''; Write-Host $m -ForegroundColor Cyan }

# Same name logic as create-accounts.ps1, so that collisions can be predicted.
function Convert-ToSamName {
    param([string]$Text)
    $t = $Text.Trim()
    $t = $t -replace 'å','a' -replace 'ä','a' -replace 'ö','o' -replace 'ø','o' -replace 'æ','a'
    $t = $t -replace 'Å','A' -replace 'Ä','A' -replace 'Ö','O' -replace 'Ø','O' -replace 'Æ','A'
    $t = $t -replace '[^a-zA-Z\-]', ''
    $t.ToLower()
}

# Short login name (pre-Windows 2000 / sAMAccountName): up to three characters from
# the first part of the given name plus up to three from the first part of the
# surname. Per Nilsson Andersson yields pernil. This is the name that carries the
# 20-character limit, and the short rule keeps it well below the limit.
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
# dot-separated. Per Nilsson Andersson yields per.nilsson.andersson.
# The UPN has no documented length limit, so this one never needs shortening.
function Get-DottedLoginName {
    param([string]$GivenName, [string]$Surname)
    $parts = @()
    foreach ($d in ($GivenName -split '\s+'))  { $r = Convert-ToSamName $d; if ($r) { $parts += $r } }
    foreach ($d in ($Surname -split '\s+')) { $r = Convert-ToSamName $d; if ($r) { $parts += $r } }
    return ($parts -join '.')
}

# Looks for an existing account that matches the person: same name (CN), same login
# name, same UPN, same mail address, or same given name and surname.
# The filter uses the LDAP names (name, sAMAccountName, userPrincipalName, mail,
# givenName, sn), which about_ActiveDirectory_Filter documents as allowed
# alongside the PowerShell property names. Empty values are skipped, so that an
# empty field can never match the entire directory.
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

# Assesses a hit. FAIL when the account prevents a clean creation: same CN in the
# target OU (DN collision) or same UPN (duplicate login). Everything else is WARN.
# Returns strings that start with "FAIL: " or "WARN: ".
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

# Deliberately null-safe version. create-accounts.ps1's own Get-Field calls
# .ToString() with no guard; this one must report the problem instead of crashing.
function Get-Field {
    param($Row, [string]$Name)
    $prop = @($Row.PSObject.Properties | Where-Object { $_.Name.Trim() -eq $Name })
    if ($prop.Count -eq 0)     { return '' }
    if ($null -eq $prop[0].Value) { return '' }
    return $prop[0].Value.ToString().Trim()
}


Write-Host ''
Write-Host 'AD bulk-account readiness check (read-only)' -ForegroundColor White
Write-Host ('Computer: {0}   Account: {1}' -f $env:COMPUTERNAME, [System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -ForegroundColor Gray


# ---------------------------------------------------------------- 0. Main script file encoding
Add-Head '0. Main script file encoding'

if (Test-Path $MainScriptPath) {
    $bytes = [System.IO.File]::ReadAllBytes($MainScriptPath)
    $hasBom = $false
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $hasBom = $true }
    $nonAscii = $false
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -gt 127) { $nonAscii = $true; break }
    }
    if (-not $nonAscii) {
        Add-Ok 'The script contains only ASCII, so the encoding does not matter.'
    }
    elseif ($hasBom) {
        Add-Ok 'The script has a UTF-8 BOM and contains characters above 127. PowerShell 5.1 reads it correctly.'
    }
    else {
        Add-Fail 'The script contains characters above 127 but has no BOM.'
        Add-Info 'Windows PowerShell 5.1 reads source code as ANSI when the BOM is missing. The string'
        Add-Info 'literals for å/ä/ö in -replace are then wrong, and login names for names with å/ä/ö'
        Add-Info 'come out wrong (the characters are stripped instead of replaced). Fix: save the file as UTF-8 with a BOM.'
    }
}
else {
    Add-Warn ('Cannot find {0}. Skipping the encoding check (pass -MainScriptPath).' -f $MainScriptPath)
}


# ---------------------------------------------------------------- 1. Module and domain
Add-Head '1. ActiveDirectory module and domain'

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-Ok 'The ActiveDirectory module is loaded.'
}
catch {
    Add-Fail ('Cannot load the ActiveDirectory module: {0}' -f $_.Exception.Message)
    Write-Host ''
    Write-Host 'Aborting: without the module nothing can be checked.' -ForegroundColor Red
    exit 1
}

try {
    $domain = Get-ADDomain -ErrorAction Stop
    Add-Ok ('Domain: {0} (NetBIOS: {1})' -f $domain.DNSRoot, $domain.NetBIOSName)
}
catch {
    Add-Fail ('Cannot read domain information: {0}' -f $_.Exception.Message)
}

try {
    $forest = Get-ADForest -ErrorAction Stop
    Add-Ok ('Forest: {0}' -f $forest.Name)
}
catch {
    Add-Warn ('Cannot read forest information: {0}' -f $_.Exception.Message)
}


# ---------------------------------------------------------------- 2. UPN suffix and mail domain
Add-Head '2. UPN suffix and mail domain'

if ($forest) {
    $validSuffixes = @()
    $validSuffixes += $domain.DNSRoot
    if ($forest.UPNSuffixes) { $validSuffixes += $forest.UPNSuffixes }
    if ($forest.Domains)     { $validSuffixes += $forest.Domains }
    $validSuffixes = $validSuffixes | Where-Object { $_ } | Select-Object -Unique

    if ($validSuffixes -contains $UpnSuffix) {
        Add-Ok ('The UPN suffix {0} exists in the forest.' -f $UpnSuffix)
    }
    else {
        Add-Fail ('The UPN suffix {0} is NOT registered in the forest.' -f $UpnSuffix)
        Add-Info 'The accounts are still created, but login with the UPN will not work until the'
        Add-Info 'suffix is added as an Alternative UPN suffix at forest level.'
        Add-Info ('Registered suffixes: {0}' -f ($validSuffixes -join ', '))
    }
}
else {
    Add-Warn 'Forest information is missing, so the UPN suffix could not be checked.'
}

if ($UpnSuffix -eq $MailDomain) {
    Add-Ok ('UPN and mail use the same domain ({0}).' -f $MailDomain)
}
else {
    Add-Warn ('UPN ({0}) and mail ({1}) use different domains. Check that both are intended.' -f $UpnSuffix, $MailDomain)
}


# ---------------------------------------------------------------- 3. Target OU
Add-Head '3. Target OU for the accounts'

$ouOk = $false
try {
    $ou = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
    Add-Ok ('OU exists: {0}' -f $ou.DistinguishedName)
    $ouOk = $true
}
catch {
    Add-Fail ('The OU does not exist or cannot be read: {0}' -f $TargetOU)
    Add-Info ('Error: {0}' -f $_.Exception.Message)
    Add-Info 'Correct $TargetOU in create-accounts.ps1 and run this check again.'
}

if ($ouOk) {
    Add-Warn 'The permission to CREATE objects in the OU cannot be verified read-only.'
    Add-Info 'Being able to read the OU does not prove that the account may create users in it.'
    Add-Info 'That only shows in a live run, so always try WhatIf mode first.'
}


# ---------------------------------------------------------------- 4. Groups
Add-Head '4. Groups the accounts will be added to'

$groupDns = @()
foreach ($group in $GroupNames) {
    try {
        $g = Get-ADGroup -Identity $group -ErrorAction Stop
        Add-Ok ('The group exists: {0} ({1} / {2})' -f $g.Name, $g.GroupScope, $g.GroupCategory)
        $groupDns += $g.DistinguishedName

        if ($g.GroupCategory -eq 'Distribution') {
            Add-Warn ('{0} is a distribution group, not a security group. It cannot be used for permissions.' -f $g.Name)
        }
        if ($ouOk) {
            $ouNc = ($TargetOU -split ',DC=', 2)[1]
            $gNc  = ($g.DistinguishedName -split ',DC=', 2)[1]
            if ($ouNc -ne $gNc) {
                Add-Fail ('The group {0} lives in a different domain/naming context than the OU. Members cannot be added across a domain boundary.' -f $g.Name)
            }
        }
    }
    catch {
        Add-Fail ('The group cannot be found or cannot be read: {0}' -f $group)
        Add-Info 'All accounts are still created, but the group step fails for every account,'
        Add-Info 'and then no password is written to the result file. Correct the group name first.'
    }
}


# ---------------------------------------------------------------- 5. Password policy
Add-Head '5. Password policy against PasswordLength'

$minLen = 0
try {
    $pol = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
    Add-Ok ('Default policy: MinPasswordLength={0}, ComplexityEnabled={1}, PasswordHistoryCount={2}, MaxPasswordAge={3}' -f $pol.MinPasswordLength, $pol.ComplexityEnabled, $pol.PasswordHistoryCount, $pol.MaxPasswordAge)
    if ($null -eq $pol.MinPasswordLength) {
        Add-Fail 'The policy responded without MinPasswordLength. Run Get-ADDefaultDomainPasswordPolicy manually: without that value there is no way to know whether the password will be accepted.'
        $minLen = 0
    }
    else {
        $minLen = [int]$pol.MinPasswordLength
        if ($PasswordLength -lt $minLen) {
            Add-Fail ('PasswordLength is {0} but the domain policy requires at least {1} characters. The accounts are still created, but without a valid password.' -f $PasswordLength, $minLen)
        }
        else {
            Add-Ok ('PasswordLength ({0}) meets the minimum length of the default policy ({1}).' -f $PasswordLength, $minLen)
        }
    }
    if (-not $pol.ComplexityEnabled) {
        Add-Warn 'ComplexityEnabled is off in the default policy. That is weaker than what Microsoft recommends.'
    }
}
catch {
    Add-Warn ('Cannot read the domain password policy: {0}' -f $_.Exception.Message)
}

$psoMinLen = 0
try {
    $psos = @()
    try {
        $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -Properties AppliesTo -ErrorAction Stop)
    }
    catch {
        $psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)
    }
    if ($psos.Count -eq 0) {
        Add-Ok 'There are no fine-grained password policies (PSO) in the domain.'
    }
    else {
        Add-Info ('{0} fine-grained password policy(ies) exist. Checking whether any of them applies to the groups above.' -f $psos.Count)
        $hit = $false
        foreach ($pso in $psos) {
            $applies = @()
            if ($pso.AppliesTo) {
                foreach ($a in $pso.AppliesTo) { $applies += $a.DistinguishedName }
            }
            $match = $false
            foreach ($dn in $groupDns) { if ($applies -contains $dn) { $match = $true } }
            if (-not $pso.AppliesTo) {
                Add-Warn ('PSO "{0}": AppliesTo could not be read, so it cannot be ruled out that it applies to the group.' -f $pso.Name)
            }
            if ($match) {
                $hit = $true
                Add-Info ('PSO "{0}" applies to one of the groups: MinPasswordLength={1}, ComplexityEnabled={2}' -f $pso.Name, $pso.MinPasswordLength, $pso.ComplexityEnabled)
                if ($null -eq $pso.MinPasswordLength) {
                    Add-Fail ('PSO "{0}" applies to the group but responded without MinPasswordLength.' -f $pso.Name)
                }
                elseif ([int]$pso.MinPasswordLength -gt $psoMinLen) { $psoMinLen = [int]$pso.MinPasswordLength }
            }
        }
        if ($hit) {
            if ($PasswordLength -lt $psoMinLen) {
                Add-Fail ('PasswordLength is {0} but a PSO that applies to the group requires {1} characters. Increase $PasswordLength.' -f $PasswordLength, $psoMinLen)
            }
            else {
                Add-Ok ('PasswordLength ({0}) also meets the PSO that applies to the group ({1}).' -f $PasswordLength, $psoMinLen)
            }
        }
        else {
            Add-Ok 'No PSO applies to the given groups. The default policy applies.'
        }
    }
}
catch {
    Add-Warn 'Could not read fine-grained password policies. Check manually whether any of them applies to the group.'
}

Add-Warn 'That this particular password is accepted can only be proven by creating an account.'
Add-Info 'New-ADUser creates the account even if the password is rejected, and the account is then not enabled.'
Add-Info 'After the run, therefore, verify that the accounts are Enabled and have PasswordLastSet set.'


# ---------------------------------------------------------------- 6. The CSV file
Add-Head '6. The CSV file: encoding, delimiter and headers'

if (-not (Test-Path $CsvPath)) {
    Add-Fail ('The CSV file does not exist: {0}' -f $CsvPath)
    Write-Host ''
    Write-Host 'Aborting: without the input file nothing more can be checked.' -ForegroundColor Red
    exit 1
}
Add-Ok ('The CSV file exists: {0}' -f $CsvPath)

$rawBytes = [System.IO.File]::ReadAllBytes($CsvPath)
$csvHasBom = $false
if ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) { $csvHasBom = $true }

if ($rawBytes.Length -eq 0) {
    Add-Fail 'The CSV file is empty (0 bytes).'
    exit 1
}

$rawText = [System.IO.File]::ReadAllText($CsvPath, [System.Text.Encoding]::GetEncoding(1252))
$rawLines = $rawText -split "\r?\n"
$headerLine = $rawLines[0]

if ($csvHasBom) {
    Add-Fail 'The file starts with a UTF-8 BOM.'
    Add-Info 'The script reads the file as cp1252, so the BOM characters end up in front of the first column name.'
    Add-Info 'The Name column is then not found, and ALL rows are skipped silently, so the result is empty.'
    Add-Info 'Fix: save the file again as "CSV (comma delimited)" or remove the BOM.'
}
else {
    Add-Ok 'The file has no BOM (matching the cp1252 read in the script).'
}

$semiCount = ([regex]::Matches($headerLine, ';')).Count
$commaCount = ([regex]::Matches($headerLine, ',')).Count
$tabCount = ([regex]::Matches($headerLine, "`t")).Count

if ($semiCount -ge $commaCount -and $semiCount -ge $tabCount -and $semiCount -gt 0) {
    Add-Ok ('The delimiter appears to be a semicolon ({0} in the header row).' -f $semiCount)
    $delimiter = ';'
}
elseif ($tabCount -gt 0 -and $tabCount -ge $commaCount) {
    Add-Fail 'The header row is tab-separated, but the script parses semicolons.'
    Add-Info 'ConvertFrom-Csv then yields a single column named after the whole header, and every row is skipped.'
    $delimiter = ';'
}
else {
    Add-Fail ('The header row looks comma-separated ({0} commas, {1} semicolons), but the script parses semicolons.' -f $commaCount, $semiCount)
    Add-Info 'Save the file again with a semicolon as the delimiter.'
    $delimiter = ';'
}

$rows = @($rawText | ConvertFrom-Csv -Delimiter $delimiter)
Add-Ok ('The file contains {0} data rows (the header row not counted).' -f $rows.Count)

if ($rows.Count -eq 0) {
    Add-Fail 'The file yielded no data rows at all. Either it is empty, or the delimiter does not match.'
    exit 1
}

if ($ExpectedRows -gt 0) {
    if ($rows.Count -eq $ExpectedRows) {
        Add-Ok ('The number of rows matches the expected count ({0}).' -f $ExpectedRows)
    }
    else {
        Add-Warn ('The number of rows is {0} but {1} was expected. Check that the whole list was exported.' -f $rows.Count, $ExpectedRows)
    }
}

$first = $rows[0]
$parsedNames = @($first.PSObject.Properties | ForEach-Object { $_.Name })
Add-Info ('Columns as the script sees them: {0}' -f ($parsedNames -join ' | '))

$expectedColumns = @('Name', 'Last Name', 'Company', 'Title', 'City')
$missingColumns = @()
foreach ($col in $expectedColumns) {
    $found = @($first.PSObject.Properties | Where-Object { $_.Name.Trim() -eq $col })
    if ($found.Count -eq 0) { $missingColumns += $col }
}
if ($missingColumns.Count -eq 0) {
    Add-Ok 'All five columns that the script reads are present with the correct names.'
}
else {
    Add-Fail ('Columns the script looks for but cannot find: {0}' -f ($missingColumns -join ', '))
    Add-Info 'Rows without Name or Last Name are skipped silently, so a typo here yields an empty result.'
}

Add-Head '6b. Empty fields - the single most important check'

# The question is not whether the first row has empty fields, but what an empty
# field BECOMES. Therefore every row and all five columns are scanned.
$nullCols = @{}
$emptyCols = @{}
$rowsWithEmpty = 0
foreach ($r in $rows) {
    $rowHasEmpty = $false
    foreach ($col in $expectedColumns) {
        $prop = @($r.PSObject.Properties | Where-Object { $_.Name.Trim() -eq $col })
        if ($prop.Count -eq 0) {
            $nullCols[$col] = $true
            $rowHasEmpty = $true
        }
        elseif ($null -eq $prop[0].Value) {
            $nullCols[$col] = $true
            $rowHasEmpty = $true
        }
        elseif ($prop[0].Value.ToString().Trim() -eq '') {
            $emptyCols[$col] = $true
            $rowHasEmpty = $true
        }
    }
    if ($rowHasEmpty) { $rowsWithEmpty++ }
}

if ($nullCols.Count -gt 0) {
    Add-Fail ('Empty fields become $null in this PowerShell version, in the column(s): {0}' -f (($nullCols.Keys | Sort-Object) -join ', '))
    Add-Info ('{0} row(s) are affected. Get-Field calls .ToString() on the value with no guard,' -f $rowsWithEmpty)
    Add-Info 'and those calls sit OUTSIDE the try block in create-accounts.ps1.'
    Add-Info 'A single such row stops the entire run in the middle of the list, after a number of'
    Add-Info 'accounts have already been created. Guard Get-Field, for example: if ($null -eq $prop.Value) { return "" }'
}
elseif ($emptyCols.Count -gt 0) {
    Add-Ok ('Empty fields become empty strings here, so Get-Field does not crash. Empty fields are in: {0}' -f (($emptyCols.Keys | Sort-Object) -join ', '))
    Add-Info ('{0} row(s) have at least one empty field. Check that this is intentional.' -f $rowsWithEmpty)
}
else {
    Add-Ok 'There are no empty fields in the five columns. The null question does not apply to this file.'
}

$emptyRows = 0
$emptyExamples = @()
foreach ($r in $rows) {
    $n = ''
    $ln = ''
    $propN = $r.PSObject.Properties | Where-Object { $_.Name.Trim() -eq 'Name' }
    $propL = $r.PSObject.Properties | Where-Object { $_.Name.Trim() -eq 'Last Name' }
    if ($propN -and $propN.Value) { $n = [string]$propN.Value }
    if ($propL -and $propL.Value) { $ln = [string]$propL.Value }
    if ([string]::IsNullOrWhiteSpace($n) -or [string]::IsNullOrWhiteSpace($ln)) {
        $emptyRows++
        if ($emptyExamples.Count -lt 5) { $emptyExamples += ('row without a name: Name="{0}" LastName="{1}"' -f $n, $ln) }
    }
}
if ($emptyRows -eq 0) {
    Add-Ok 'No rows are missing a name. No row is skipped.'
}
else {
    Add-Warn ('{0} row(s) lack Name or Last Name and are skipped silently by the script.' -f $emptyRows)
    foreach ($e in $emptyExamples) { Add-Info $e }
}


# ---------------------------------------------------------------- 7. Predicted accounts and collisions
Add-Head '7. Accounts the script will create (predicted)'

$predicted = @()
foreach ($r in $rows) {
    $givenName = Get-Field $r 'Name'
    $surname   = Get-Field $r 'Last Name'
    if ([string]::IsNullOrWhiteSpace($givenName) -or [string]::IsNullOrWhiteSpace($surname)) { continue }

    $shortName  = Get-ShortLoginName -Fornamn $givenName -Efternamn $surname
    $dottedName = Get-DottedLoginName          -Fornamn $givenName -Efternamn $surname
    $display   = ($givenName + ' ' + $surname)

    $predicted += [PSCustomObject]@{
        Display   = $display
        BaseSam   = $shortName
        Sam       = $shortName
        Truncated = ($shortName.Length -gt 20)
        Empty     = [string]::IsNullOrWhiteSpace($shortName)
        Upn       = ($dottedName + '@' + $UpnSuffix)
        Mail      = ($dottedName + '@' + $MailDomain)
    }
}
Add-Ok ('{0} rows yield a predicted account.' -f $predicted.Count)
Add-Info 'The names come out as follows (pre-Windows 2000 -> UPN and mail address):'
foreach ($p in ($predicted | Select-Object -First 5)) {
    Add-Info ('  {0,-9} -> {1}' -f $p.Sam, $p.Upn)
}
$longOnes = @($predicted | Where-Object { $_.Sam.Length -gt 6 })
if ($longOnes.Count -eq 0) {
    Add-Ok 'All short login names are at most 6 characters, so the 20-character limit cannot be reached.'
}
else {
    Add-Warn ('{0} short names are longer than 6 characters. Check the name rule.' -f $longOnes.Count)
}

$emptySams = @($predicted | Where-Object { $_.Empty })
if ($emptySams.Count -gt 0) {
    Add-Fail ('{0} row(s) yield an empty login name after character stripping.' -f $emptySams.Count)
    foreach ($e in ($emptySams | Select-Object -First 5)) { Add-Info ('DisplayName "{0}" yields "{1}"' -f $e.Display, $e.BaseSam) }
}
else {
    Add-Ok 'No row yields an empty login name.'
}

$truncated = @($predicted | Where-Object { $_.Truncated })
if ($truncated.Count -gt 0) {
    Add-Warn ('{0} login names are longer than 20 characters and are truncated. Check that they are still unique.' -f $truncated.Count)
    foreach ($t in ($truncated | Select-Object -First 5)) { Add-Info ('"{0}" -> "{1}"' -f $t.BaseSam, $t.Sam) }
}
else {
    Add-Ok 'No login names need to be truncated to 20 characters.'
}

$dupSam = @($predicted | Group-Object Sam | Where-Object { $_.Count -gt 1 })
if ($dupSam.Count -gt 0) {
    Add-Warn ('{0} login names collide within the file. A numeric suffix is appended (for example name1).' -f $dupSam.Count)
    foreach ($d in ($dupSam | Select-Object -First 5)) { Add-Info ('{0} x{1}' -f $d.Name, $d.Count) }
}
else {
    Add-Ok 'No login names collide within the file.'
}

$dupDisplay = @($predicted | Group-Object Display | Where-Object { $_.Count -gt 1 })
if ($dupDisplay.Count -gt 0) {
    Add-Fail ('{0} display names are identical within the file. The script does NOT check this.' -f $dupDisplay.Count)
    Add-Info 'New-ADUser -Name sets the CN, and the CN must be unique in the OU. The second entry fails'
    Add-Info 'with "object already exists", is logged as FAIL, and gets no password.'
    foreach ($d in ($dupDisplay | Select-Object -First 5)) { Add-Info ('{0} x{1}' -f $d.Name, $d.Count) }
}
else {
    Add-Ok 'All display names are unique within the file (no CN collision between rows).'
}


# ---------------------------------------------------------------- 8. Existing people in AD
Add-Head '8. Existing people and taken names in AD'

$peopleFails = 0
$peopleWarns = 0
$suffixCount = 0
$personErrors = 0
$shownFails = 0
$shownWarns = 0

foreach ($p in $predicted) {
    try {
        $hits = Get-ExistingPerson -DisplayName $p.Display -Sam $p.Sam -Upn $p.Upn -Mail $p.Mail
    }
    catch {
        $personErrors++
        continue
    }
    foreach ($h in $hits) {
        foreach ($f in (Get-PersonFindings -Candidate $h -DisplayName $p.Display -Sam $p.Sam -Upn $p.Upn -Mail $p.Mail -TargetOU $TargetOU)) {
            if ($f.StartsWith('FAIL:')) {
                $peopleFails++
                if ($shownFails -lt 8) { Add-Fail ('{0}: {1}' -f $p.Display, $f.Substring(5).Trim()); $shownFails++ }
            }
            else {
                $peopleWarns++
                if ($shownWarns -lt 8) { Add-Warn ('{0}: {1}' -f $p.Display, $f.Substring(6).Trim()); $shownWarns++ }
            }
            if ($f -like '*login name*') { $suffixCount++ }
        }
    }
}

if ($personErrors -gt 0) {
    Add-Warn ('{0} searches against AD failed. The result is incomplete, run again.' -f $personErrors)
}
if ($peopleFails -eq 0 -and $peopleWarns -eq 0) {
    Add-Ok ('None of the {0} people already exists in AD, and no name, no UPN and no mail address is taken.' -f $predicted.Count)
}
else {
    Add-Info ('{0} FAIL and {1} warnings in total. Only the first of each is shown above.' -f $peopleFails, $peopleWarns)
}
if ($peopleFails -gt 0) {
    Add-Info 'The creator aborts on FAIL rows unless you run it with -AllowExistingPerson.'
}
if ($suffixCount -gt 0) {
    Add-Info ('{0} login names are taken and get a numeric suffix at creation.' -f $suffixCount)
}


# ---------------------------------------------------------------- Summary
Add-Head 'Summary'

Write-Host ''
Write-Host ('  Checks: {0}   OK: {1}   Warnings: {2}   Failures: {3}' -f $script:Total, ($script:Total - $script:Fails - $script:Warns), $script:Warns, $script:Fails)
Write-Host ''

if ($script:Fails -gt 0) {
    Write-Host '  AT LEAST ONE FAILURE MUST BE FIXED BEFORE THE SCRIPT RUNS AGAINST PRODUCTION.' -ForegroundColor Red
    Write-Host ''
    exit 1
}

Write-Host '  No failures found. Next steps:' -ForegroundColor Green
Write-Host '    1. Run create-accounts.ps1 with $WhatIfMode = $true and review the output line by line.'
Write-Host '    2. Check that the OU, groups and mail addresses are correct for every person.'
Write-Host '    3. Set $WhatIfMode = $false and run for real.'
Write-Host ''
Write-Host '  Remember: the script creates the account even if the policy rejects the password.' -ForegroundColor Yellow
Write-Host '  Verify afterwards:  Get-ADUser -Filter * -SearchBase "<OU>" -Properties PasswordLastSet,Enabled'
Write-Host '  and check that every new account is Enabled and has PasswordLastSet set.' -ForegroundColor Yellow
Write-Host ''
exit 0
