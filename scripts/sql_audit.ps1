param (
    [string]$SqlInstance = "localhost",
    [string]$OutDir = "./output"
)

$results = @{}

# === Login Overview ===
$logins = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "SELECT name, is_disabled, type_desc FROM sys.sql_logins"
$results["logins"] = $logins

# Check if 'sa' is disabled
$saStatus = $logins | Where-Object { $_.name -eq "sa" }
$results["sa_disabled"] = $saStatus.is_disabled -eq 1

# === AuditLevel Registry Setting ===
$possiblePaths = Get-ChildItem "HKLM:\Software\Microsoft\Microsoft SQL Server" |
    Where-Object { $_.PSChildName -match "^MSSQL\d+\." } |
    ForEach-Object { "HKLM:\Software\Microsoft\Microsoft SQL Server\$($_.PSChildName)\MSSQLServer" }

$foundPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($foundPath) {
    $auditLevel = (Get-ItemProperty -Path $foundPath -Name AuditLevel -ErrorAction SilentlyContinue).AuditLevel
    $results["failed_login_audit_level"] = $auditLevel
} else {
    $results["failed_login_audit_level"] = "AuditLevel registry not found"
}

# === TDE (Transparent Data Encryption) Check ===
$tde = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query "
SELECT name, is_encrypted FROM sys.databases WHERE is_encrypted = 1"
$results["tde_enabled_databases"] = $tde

# === NEW: Role Membership Check ===
$roles = Invoke-Sqlcmd -ServerInstance $SqlInstance -Database "master" -Query @"
SELECT 
    l.name AS login_name,
    r.name AS role_name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.server_principals l ON rm.member_principal_id = l.principal_id
"@

$results["role_membership"] = $roles

# === NEW: Schema Modifications (Last 30 Days) ===
$schemaChanges = Invoke-Sqlcmd -ServerInstance $SqlInstance -Database "master" -Query @"
SELECT 
    name, 
    type_desc, 
    create_date, 
    modify_date 
FROM sys.objects 
WHERE modify_date >= DATEADD(day, -30, GETDATE())
"@

$results["schema_changes"] = $schemaChanges

# === NEW: SQL Server Audit Configuration (Safe Version) ===
try {
    $sqlAudit = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT 
    name,
    audit_guid,
    type_desc,
    is_state_enabled
FROM sys.server_audits
"@

    $results["sql_audit_config"] = $sqlAudit
} catch {
    $results["sql_audit_config"] = "Audit feature not available or access denied"
}


# ===== NEW: SQL Server Backup Encryption Check =====
try {
    $backups = Invoke-Sqlcmd -ServerInstance $SqlInstance -Database "msdb" -Query @"
SELECT 
    b.database_name,
    b.backup_start_date,
    b.backup_finish_date,
    b.type AS backup_type,
    CASE 
        WHEN b.encryptor_thumbprint IS NULL THEN 'Not Encrypted'
        ELSE 'Encrypted'
    END AS encryption_status
FROM msdb.dbo.backupset b
WHERE backup_start_date >= DATEADD(day, -30, GETDATE())
ORDER BY backup_finish_date DESC
"@

    $results["backup_encryption_status"] = $backups
} catch {
    $results["backup_encryption_status"] = "Backup encryption check failed: $_"
}


# ===== NEW: SQL Server Elevated Role Anomaly Check =====
try {
    $elevatedRoles = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT 
    l.name AS login_name,
    r.name AS role_name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
JOIN sys.server_principals l ON rm.member_principal_id = l.principal_id
WHERE r.name IN ('sysadmin', 'securityadmin', 'serveradmin', 'setupadmin')
ORDER BY r.name, l.name
"@

    $results["elevated_permissions"] = $elevatedRoles
} catch {
    $results["elevated_permissions"] = "Elevated permissions check failed: $_"
}


# === Save Final Output ===
$results | ConvertTo-Json -Depth 6 | Out-File -FilePath "$OutDir/sql_report.json"
