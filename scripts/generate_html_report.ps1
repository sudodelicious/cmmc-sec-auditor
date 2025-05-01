param (
    [string]$ReportPath = "./output/report.json",
    [string]$HtmlPath = "./output/report.html"
)

# Load report
$report = Get-Content $ReportPath | ConvertFrom-Json

# Assign sections properly
$status = $report.summary_status
$cmmc = $report.cmmc_mapping
$iis = $report.iis
$sql = $report.sql

# Debug (optional)
Write-Host "DEBUG: Summary keys loaded:" ($status.PSObject.Properties.Name -join ", ")
Write-Host "DEBUG: CMMC keys loaded:" ($cmmc.PSObject.Properties.Name -join ", ")

# Start building HTML
$html = @"
<html>
<head>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    h1, h2 { color: #333; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    .pass { background-color: #d4edda; }
    .fail { background-color: #f8d7da; }
    pre { background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; overflow-x: auto; }
  </style>
</head>
<body>
<h1>CMMC Audit Report</h1>
<p><strong>Generated:</strong> $($report.generated_at.DateTime.ToString())</p>
"@

# === Audit Summary Section ===
$html += "<h2>Audit Summary</h2><table><tr><th>Check</th><th>Status</th></tr>"

foreach ($prop in $status.PSObject.Properties) {
    $class = if ($prop.Value -match "PASS") { "pass" } elseif ($prop.Value -match "FAIL") { "fail" } else { "" }
    $html += "<tr class='$class'><td>$($prop.Name)</td><td>$($prop.Value)</td></tr>`n"
}

$html += "</table>"

# === CMMC Control Mapping Section ===
$html += "<h2>CMMC Control Mapping</h2><table><tr><th>Control</th><th>Description</th></tr>"

foreach ($prop in $cmmc.PSObject.Properties) {
    $html += "<tr><td>$($prop.Name)</td><td>$($prop.Value)</td></tr>`n"
}

$html += "</table>"

# ===== IIS Logging Status =====
if ($iis.iis_logging_status) {
    $html += "</table><h2>IIS Logging Status</h2><p><strong>Status:</strong> $($iis.iis_logging_status)</p>"
}

# ===== IIS applicationHost.config Permissions =====
if ($iis.applicationHost_config_acl) {
    $html += "</table><h2>applicationHost.config File Permissions</h2><table><tr><th>User/Group</th><th>Rights</th><th>Type</th></tr>"
    foreach ($perm in $iis.applicationHost_config_acl) {
        $html += "<tr><td>$($perm.IdentityReference)</td><td>$($perm.FileSystemRights)</td><td>$($perm.AccessControlType)</td></tr>"
    }
    $html += "</table>"
}

# ===== SQL Server Elevated Permissions =====
if ($sql.elevated_permissions) {
    if ($sql.elevated_permissions -is [string]) {
        $html += "</table><h2>SQL Server Elevated Permissions</h2><p><strong>Status:</strong> $($sql.elevated_permissions)</p>"
    }
    elseif ($sql.elevated_permissions.Count -gt 0) {
        $html += "</table><h2>SQL Server Elevated Permissions</h2><table><tr><th>Login Name</th><th>Role</th></tr>"
        foreach ($perm in $sql.elevated_permissions) {
            $html += "<tr><td>$($perm.login_name)</td><td>$($perm.role_name)</td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "</table><h2>SQL Server Elevated Permissions</h2><p>No elevated role memberships found.</p>"
    }
}

# ===== SQL Server Backup Encryption Status =====
if ($sql.backup_encryption_status) {
    if ($sql.backup_encryption_status -is [string]) {
        $html += "</table><h2>SQL Server Backup Encryption</h2><p><strong>Status:</strong> $($sql.backup_encryption_status)</p>"
    }
    elseif ($sql.backup_encryption_status.Count -gt 0) {
        $html += "</table><h2>SQL Server Backup Encryption (Last 30 Days)</h2><table><tr><th>Database</th><th>Backup Type</th><th>Start</th><th>Finish</th><th>Encryption Status</th></tr>"
        foreach ($b in $sql.backup_encryption_status) {
            $html += "<tr><td>$($b.database_name)</td><td>$($b.backup_type)</td><td>$($b.backup_start_date)</td><td>$($b.backup_finish_date)</td><td>$($b.encryption_status)</td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "</table><h2>SQL Server Backup Encryption</h2><p>No backups found in the last 30 days.</p>"
    }
}

# ===== SQL Server Audit Configuration =====
if ($sql.sql_audit_config) {
    if ($sql.sql_audit_config -is [string]) {
        $html += "</table><h2>SQL Server Audit Configuration</h2><p><strong>Status:</strong> $($sql.sql_audit_config)</p>"
    }
    elseif ($sql.sql_audit_config.Count -gt 0) {
        $html += "</table><h2>SQL Server Audit Configuration</h2><table><tr><th>Name</th><th>Type</th><th>Enabled</th></tr>"
        foreach ($audit in $sql.sql_audit_config) {
            $html += "<tr><td>$($audit.name)</td><td>$($audit.type_desc)</td><td>$($audit.is_state_enabled)</td></tr>"
        }
        $html += "</table>"
    }
    else {
        $html += "</table><h2>SQL Server Audit Configuration</h2><p>No audits configured on this SQL Server.</p>"
    }
}

# ===== Windows Firewall Status =====
try {
    $fw = Get-Content "./output/windows_firewall.json" | ConvertFrom-Json
    if ($fw.profiles -and $fw.profiles.Count -gt 0) {
        $html += "</table><h2>Windows Firewall Configuration</h2><table><tr><th>Profile</th><th>Enabled</th><th>Inbound</th><th>Outbound</th></tr>"
        foreach ($p in $fw.profiles) {
            $html += "<tr><td>$($p.Name)</td><td>$($p.Enabled)</td><td>$($p.DefaultInboundAction)</td><td>$($p.DefaultOutboundAction)</td></tr>"
        }
        $html += "</table>"
    }
} catch {
    $html += "</table><h2>Windows Firewall Configuration</h2><p>Unable to load firewall data.</p>"
}

# ===== Windows Account Lockout Policy =====
try {
    $lockout = Get-Content "./output/account_lockout_summary.json" | ConvertFrom-Json
    $html += "</table><h2>Account Lockout Policy</h2><table><tr><th>Setting</th><th>Value</th></tr>"
    foreach ($key in $lockout.PSObject.Properties.Name) {
        $html += "<tr><td>$key</td><td>$($lockout.$key)</td></tr>"
    }
    $html += "</table>"
} catch {
    $html += "</table><h2>Account Lockout Policy</h2><p>Unable to load lockout policy data.</p>"
}


# ===== CMMC Practice Coverage Matrix =====
try {
    $cmmcMappings = Import-PowerShellDataFile -Path ".\scripts\cmmc_mappings.psd1"

    $html += "</table><h2>CMMC Practice Coverage Matrix</h2><table><tr><th>Practice</th><th>Description</th><th>Checks</th><th>Status</th></tr>"

    foreach ($practice in $cmmcMappings.Keys) {
        $mapping = $cmmcMappings[$practice]
        $description = $mapping.description
        $relatedChecks = $mapping.checks -join ", "

        $statuses = @()
        foreach ($check in $mapping.checks) {
            if ($status.ContainsKey($check)) {
                $statuses += $status[$check]
            } else {
                $statuses += "Manual Review"
            }
        }

        $finalStatus = if ($statuses -contains "[FAIL]") { "[FAIL]" } elseif ($statuses -contains "Manual Review") { "Manual Review" } else { "[PASS]" }

        $html += "<tr><td>$practice</td><td>$description</td><td>$relatedChecks</td><td>$finalStatus</td></tr>`n"
    }

    $html += "</table>"
} catch {
    $html += "</table><h2>CMMC Practice Coverage Matrix</h2><p>Unable to load CMMC mappings.</p>"
}

# ===== Raw Full JSON at the End =====
$html += "</table><h2>Full Raw JSON</h2><pre>$($report | ConvertTo-Json -Depth 6)</pre></body></html>"

# Save the HTML
$html | Out-File -FilePath $HtmlPath
Write-Host "HTML report generated at $HtmlPath"
