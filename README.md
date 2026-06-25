# AD Learning Path 17 — Bulk Provision Users with PowerShell

## Objective
Provision multiple users from a validated CSV with a full preflight phase, duplicate detection, secure initial passwords, deterministic reporting, and controlled rollback.

## Prerequisites
- Users OU exists
- ActiveDirectory PowerShell module
- Approved CSV with no plaintext passwords
- Permission to read OUs/users and create users in the target OU

## CSV columns

```text
GivenName,Surname,SamAccountName,UserPrincipalName,Department,Title,OU
```

## Safety model
1. Import the entire CSV and verify all required columns.
2. Validate every row before creating any object.
3. Reject duplicate `SamAccountName` and `UserPrincipalName` values inside the CSV.
4. Confirm every target OU exists.
5. Confirm each SAM account name and UPN is unused in Active Directory.
6. Abort the entire run when any preflight error exists.
7. Record the created object's GUID and distinguished name for controlled rollback.
8. Remove only objects whose GUIDs were recorded by the current run.

## Implementation

```powershell
#requires -Version 5.1
#requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath = (Join-Path $PSScriptRoot 'users.csv'),

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ReportDirectory = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-LdapFilterValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    $escaped = $Value -replace '\\', '\5c'
    $escaped = $escaped -replace '\*', '\2a'
    $escaped = $escaped -replace '\(', '\28'
    $escaped = $escaped -replace '\)', '\29'
    $escaped = $escaped -replace "`0", '\00'
    return $escaped
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    throw "CSV file not found: $CsvPath"
}

New-Item -Path $ReportDirectory -ItemType Directory -Force | Out-Null

$runId = [guid]::NewGuid().Guid
$rows = @(Import-Csv -LiteralPath $CsvPath)
$requiredColumns = @(
    'GivenName',
    'Surname',
    'SamAccountName',
    'UserPrincipalName',
    'Department',
    'Title',
    'OU'
)

if ($rows.Count -eq 0) {
    throw 'The CSV contains no data rows.'
}

$actualColumns = @($rows[0].PSObject.Properties.Name)
$missingColumns = @($requiredColumns | Where-Object { $_ -notin $actualColumns })
if ($missingColumns.Count -gt 0) {
    throw "Missing required CSV columns: $($missingColumns -join ', ')"
}

$duplicateSams = @(
    $rows |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.SamAccountName) } |
        Group-Object { $_.SamAccountName.Trim().ToLowerInvariant() } |
        Where-Object Count -gt 1 |
        Select-Object -ExpandProperty Name
)

$duplicateUpns = @(
    $rows |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName) } |
        Group-Object { $_.UserPrincipalName.Trim().ToLowerInvariant() } |
        Where-Object Count -gt 1 |
        Select-Object -ExpandProperty Name
)

$preflight = New-Object System.Collections.Generic.List[object]

for ($index = 0; $index -lt $rows.Count; $index++) {
    $row = $rows[$index]
    $rowNumber = $index + 2
    $errors = New-Object System.Collections.Generic.List[string]

    foreach ($column in $requiredColumns) {
        if ([string]::IsNullOrWhiteSpace([string]$row.$column)) {
            $errors.Add("$column is empty")
        }
    }

    $sam = ([string]$row.SamAccountName).Trim()
    $upn = ([string]$row.UserPrincipalName).Trim()
    $ou = ([string]$row.OU).Trim()

    if ($sam -and $sam.ToLowerInvariant() -in $duplicateSams) {
        $errors.Add("Duplicate SamAccountName in CSV: $sam")
    }

    if ($upn -and $upn.ToLowerInvariant() -in $duplicateUpns) {
        $errors.Add("Duplicate UserPrincipalName in CSV: $upn")
    }

    if ($ou) {
        try {
            Get-ADOrganizationalUnit -Identity $ou -ErrorAction Stop | Out-Null
        }
        catch {
            $errors.Add("Target OU does not exist or is inaccessible: $ou")
        }
    }

    if ($sam) {
        try {
            if (Get-ADUser -Identity $sam -ErrorAction SilentlyContinue) {
                $errors.Add("SamAccountName already exists in Active Directory: $sam")
            }
        }
        catch {
            $errors.Add("Could not validate SamAccountName '$sam': $($_.Exception.Message)")
        }
    }

    if ($upn) {
        try {
            $escapedUpn = ConvertTo-LdapFilterValue -Value $upn
            $existingUpn = Get-ADUser -LDAPFilter "(userPrincipalName=$escapedUpn)" `
                -ResultSetSize 1 -ErrorAction Stop
            if ($existingUpn) {
                $errors.Add("UserPrincipalName already exists in Active Directory: $upn")
            }
        }
        catch {
            $errors.Add("Could not validate UserPrincipalName '$upn': $($_.Exception.Message)")
        }
    }

    $preflight.Add([pscustomobject]@{
        RowNumber         = $rowNumber
        SamAccountName    = $sam
        UserPrincipalName = $upn
        OU                = $ou
        IsValid           = ($errors.Count -eq 0)
        Errors            = ($errors -join '; ')
    })
}

$preflightPath = Join-Path $ReportDirectory "preflight-$runId.csv"
$preflight | Export-Csv -LiteralPath $preflightPath -NoTypeInformation -Encoding UTF8

$invalidRows = @($preflight | Where-Object { -not $_.IsValid })
if ($invalidRows.Count -gt 0) {
    $invalidRows | Format-Table -AutoSize | Out-Host
    throw "Preflight failed for $($invalidRows.Count) row(s). No users were created. Review $preflightPath"
}

$initialPassword = Read-Host 'Approved temporary password' -AsSecureString
if ($initialPassword.Length -eq 0) {
    throw 'The temporary password cannot be empty.'
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($row in $rows) {
    $sam = $row.SamAccountName.Trim()

    try {
        $createdUser = New-ADUser `
            -Name "$($row.GivenName.Trim()) $($row.Surname.Trim())" `
            -GivenName $row.GivenName.Trim() `
            -Surname $row.Surname.Trim() `
            -SamAccountName $sam `
            -UserPrincipalName $row.UserPrincipalName.Trim() `
            -Department $row.Department.Trim() `
            -Title $row.Title.Trim() `
            -Path $row.OU.Trim() `
            -AccountPassword $initialPassword `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -PassThru `
            -ErrorAction Stop

        $results.Add([pscustomobject]@{
            RunId             = $runId
            SamAccountName    = $sam
            Status            = 'Created'
            ObjectGUID        = [string]$createdUser.ObjectGUID
            DistinguishedName = $createdUser.DistinguishedName
            Error             = $null
        })
    }
    catch {
        $results.Add([pscustomobject]@{
            RunId             = $runId
            SamAccountName    = $sam
            Status            = 'Failed'
            ObjectGUID        = $null
            DistinguishedName = $null
            Error             = $_.Exception.Message
        })
    }
}

$resultPath = Join-Path $ReportDirectory "provision-results-$runId.csv"
$results | Export-Csv -LiteralPath $resultPath -NoTypeInformation -Encoding UTF8

$results | Format-Table -AutoSize | Out-Host
Write-Host "Provisioning report: $resultPath"
```

## Validation

```powershell
$Report = Import-Csv .\provision-results-<run-guid>.csv
$Report | Group-Object Status

$Report |
    Where-Object Status -eq 'Created' |
    ForEach-Object {
        Get-ADUser -Identity $_.ObjectGUID `
            -Properties Department,Title,Enabled,UserPrincipalName
    } |
    Select-Object SamAccountName,UserPrincipalName,Department,Title,Enabled,ObjectGUID
```

Replace `<run-guid>` with the GUID shown in the generated report filename.

## Controlled rollback
First run with `-WhatIf`. The rollback resolves each user by the recorded immutable object GUID rather than by a reused account name.

```powershell
$Report = Import-Csv .\provision-results-<run-guid>.csv

$Report |
    Where-Object { $_.Status -eq 'Created' -and $_.ObjectGUID } |
    ForEach-Object {
        $user = Get-ADUser -Identity $_.ObjectGUID -ErrorAction Stop

        if ($user.DistinguishedName -ne $_.DistinguishedName) {
            throw "Identity mismatch for recorded object GUID $($_.ObjectGUID)."
        }

        Remove-ADUser -Identity $user.ObjectGUID -Confirm:$true -WhatIf
    }
```

Remove `-WhatIf` only after reviewing every resolved object and the approved rollback record.

## Evidence
Commit only a sanitized CSV sample, preflight report, provision report, created-user inventory, failure log, rollback record, and final result under `evidence/`.

## Troubleshooting
- Preflight failure: correct every reported row before rerunning; no objects are created while validation errors exist.
- Password failure: inspect the effective domain or fine-grained password policy.
- Partial creation failure: use the run-specific result report to identify exactly which immutable object GUIDs were created.
- Directory query failure: confirm RSAT/module availability, permissions, DNS and domain-controller connectivity.

## Security notes
Never store passwords in CSV or Git. Treat source identity data and generated reports as sensitive. Use delegated least privilege and retain rollback evidence only as long as required.

## Next activity
`AD-Learning-Path-18-Manage-Domain-Computer-Accounts`
