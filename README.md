# AD Learning Path 17 — Bulk Provision Users with PowerShell

## Objective
Provision multiple users from a validated CSV with duplicate checks, secure initial passwords, logging, and controlled rollback.

## Prerequisites
- Users OU exists
- ActiveDirectory PowerShell module
- Approved CSV with no plaintext passwords
- Permission to create users in the target OU

## CSV columns
`GivenName,Surname,SamAccountName,UserPrincipalName,Department,Title,OU`

## Setup
1. Validate required fields, duplicate identities, UPN uniqueness, and OU existence before creating anything.
2. Prompt once for a secure temporary password or generate passwords outside the repository.
3. Create users with `ChangePasswordAtLogon`.
4. Export a per-row success/failure report.
5. Roll back only objects recorded as created by the current run.

```powershell
$Rows = Import-Csv .\users.csv
$InitialPassword = Read-Host 'Approved temporary password' -AsSecureString
$Results = foreach ($Row in $Rows) {
    try {
        if (Get-ADUser -Filter "SamAccountName -eq '$($Row.SamAccountName)'" -ErrorAction SilentlyContinue) {
            throw 'User already exists'
        }
        Get-ADOrganizationalUnit -Identity $Row.OU -ErrorAction Stop | Out-Null
        New-ADUser -Name "$($Row.GivenName) $($Row.Surname)" `
            -GivenName $Row.GivenName -Surname $Row.Surname `
            -SamAccountName $Row.SamAccountName -UserPrincipalName $Row.UserPrincipalName `
            -Department $Row.Department -Title $Row.Title -Path $Row.OU `
            -AccountPassword $InitialPassword -Enabled $true -ChangePasswordAtLogon $true
        [pscustomobject]@{ User=$Row.SamAccountName; Status='Created'; Error=$null }
    } catch {
        [pscustomobject]@{ User=$Row.SamAccountName; Status='Failed'; Error=$_.Exception.Message }
    }
}
$Results | Export-Csv .\provision-results.csv -NoTypeInformation
```

## Validation
```powershell
Import-Csv .\provision-results.csv | Group-Object Status
Get-ADUser -SearchBase 'OU=Users,DC=corp,DC=lab' -Filter * -Properties Department,Title,Enabled |
    Select-Object SamAccountName,UserPrincipalName,Department,Title,Enabled
```

## Evidence
Commit only a sanitized CSV sample, validation output, provision report, created-user inventory, failure log, rollback record, and final result under `evidence/`.

## Troubleshooting
- Partial run: use the report to distinguish created, skipped, and failed rows.
- Password failures: inspect the effective password policy.
- Filter errors: validate and escape input instead of trusting external CSV data.

## Security notes
Never store passwords in CSV or Git. Treat source identity data as sensitive. Use duplicate checks and least privilege.

## Cleanup
Disable and review test accounts, then remove only distinguished names recorded as created by this run.

## References
- Microsoft Learn: `New-ADUser`
- Microsoft Learn: PowerShell error handling

## Next activity
`AD-Learning-Path-18-Manage-Domain-Computer-Accounts`
