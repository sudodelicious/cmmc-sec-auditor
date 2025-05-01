param (
    [string]$SqlInstance = "localhost",
    [string]$SitePath = "IIS:\",
    [string]$OutDir = "./output"
)

# Create output folder if it doesn't exist
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "`n[+] Running IIS audit..."
.\scripts\iis_audit.ps1 -SitePath $SitePath -OutDir $OutDir

Write-Host "[+] Running SQL Server audit..."
.\scripts\sql_audit.ps1 -SqlInstance $SqlInstance -OutDir $OutDir

Write-Host "[+] Running Windows Audit Policy Check..."
.\scripts\windows_auditpol.ps1 -OutDir $OutDir

Write-Host "[+] Running Windows Firewall Check..."
.\scripts\windows_firewall_check.ps1 -OutDir $OutDir

Write-Host "[+] Running Account Lockout Policy Check..."
.\scripts\account_lockout_check.ps1 -OutDir $OutDir


# Load audit results
$iis = Get-Content "$OutDir/iis_report.json" | ConvertFrom-Json
$sql = Get-Content "$OutDir/sql_report.json" | ConvertFrom-Json

# (Optional) Load other Windows results if needed

# === Build Audit Summary ===
$summary = @{}

# IIS Checks
$summary["iis_https_redirect"] = if ($iis.https_redirect) { "[PASS]" } else { "[FAIL]" }
$summary["iis_hsts"] = if ($iis.hsts -eq "Enabled") { "[PASS]" } else { "[FAIL]" }
$summary["iis_x_frame_options"] = if ($iis.'header_X-Frame-Options' -ne "Missing") { "[PASS]" } else { "[FAIL]" }
$summary["iis_x_content_type_options"] = if ($iis.'header_X-Content-Type-Options' -ne "Missing") { "[PASS]" } else { "[FAIL]" }
$summary["iis_referrer_policy"] = if ($iis.'header_Referrer-Policy' -ne "Missing") { "[PASS]" } else { "[FAIL]" }
$summary["iis_tls_1_2_enabled"] = if ($iis.tls_1_2_enabled -eq "Yes") { "[PASS]" } else { "[FAIL]" }
$summary["iis_tls_1_0_disabled"] = if ($iis.tls_1_0_enabled -eq "No") { "[PASS]" } else { "[FAIL]" }
$summary["iis_applicationhost_acl"] = if ($iis.applicationHost_config_acl) { "[PASS]" } else { "[FAIL]" }

# SQL Server Checks
$summary["sql_sa_account_disabled"] = if ($sql.sa_disabled -eq $true) { "[PASS]" } else { "[FAIL]" }
$summary["sql_tde_enabled"] = if ($sql.tde_enabled_databases.Count -gt 0) { "[PASS]" } else { "[FAIL]" }
$summary["sql_audit_configured"] = if (($sql.sql_audit_config -is [System.Collections.IEnumerable]) -and ($sql.sql_audit_config.Count -gt 0)) { "[PASS]" } else { "[FAIL]" }
$summary["sql_encrypted_backups"] = if (($sql.backup_encryption_status | Where-Object { $_.encryption_status -eq "Not Encrypted" }).Count -eq 0) { "[PASS]" } else { "[FAIL]" }
$summary["sql_no_unauthorized_sysadmins"] = if ($sql.elevated_permissions.Count -le 2) { "[PASS]" } else { "[FAIL]" } # Allow just SQL Agent and yourself maybe

# === Build CMMC Control Mapping ===
$cmmc = @{
    "AC.L1-3.1.1" = "IIS HTTPS enforced"
    "AC.L2-3.1.2" = "Account lockout threshold set"
    "IA.L1-3.5.2" = "SQL sa disabled, secure logins"
    "SC.L2-3.13.11" = "SQL Server TDE enabled (data at rest encryption)"
    "SC.L2-3.13.8" = "TLS 1.2 enforced, 1.0 disabled on IIS"
    "AU.L2-3.3.1" = "SQL Audit and Windows Audit Policy enabled"
    "AU.L2-3.3.2" = "IIS logging enabled"
    "CM.L2-3.4.6" = "applicationHost.config ACLs secured"
}

# === Save final report
$report = @{
    generated_at = (Get-Date)
    summary_status = $summary
    iis = $iis
    sql = $sql
    cmmc_mapping = $cmmc
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath "$OutDir/report.json"


# Build audit summary
$summary = @{
    iis_https_redirect = if ($iis.https_redirect) { "[PASS]" } else { "[FAIL]" }
    iis_hsts           = if ($iis.hsts -ne "Missing") { "[PASS]" } else { "[FAIL]" }
    sql_sa_disabled    = if ($sql.sa_disabled -eq $true) { "[PASS]" } else { "[FAIL]" }
    sql_tde_enabled    = if ($sql.tde_enabled_databases.Count -gt 0) { "[PASS]" } else { "[FAIL]" }
}

# Map CMMC controls
$cmmc = @{
    "AC.L1-3.1.1"       = "IIS: HTTPS + HSTS"
    "IA.L1-3.5.2"       = "SQL: Disable sa account"
    "SC.L2-3.13.11"     = "SQL: TDE encryption enabled"
}

# Save final report
$report = @{
    generated_at    = (Get-Date)
    summary_status  = $summary
    iis             = $iis
    sql             = $sql
    cmmc_mapping    = $cmmc
}
$report | ConvertTo-Json -Depth 6 | Out-File "$OutDir/report.json"

# Generate HTML report
Write-Host "[+] Generating HTML report..."
.\scripts\generate_html_report.ps1 -ReportPath "$OutDir/report.json" -HtmlPath "$OutDir/report.html"

# Print summary
Write-Host "`n===== CMMC AUDIT SUMMARY =====" -ForegroundColor Cyan
$summary.GetEnumerator() | ForEach-Object {
    $color = if ($_.Value -match "PASS") { "Green" } elseif ($_.Value -match "FAIL") { "Red" } else { "Gray" }
    Write-Host ("{0,-30} {1}" -f $_.Key, $_.Value) -ForegroundColor $color
}
Write-Host ""
Write-Host "Full report saved to: $OutDir/report.html"
Write-Host "Open the HTML file in your browser and use 'Print > Save as PDF' if needed."

# Automatically open the HTML report
Start-Process "$OutDir/report.html"
