param (
    [string]$SitePath = "IIS:\",
    [string]$OutDir = "./output"
)

Import-Module WebAdministration
$results = @{}

# ====== ORIGINAL SERVER-LEVEL CHECKS ======

# Check for HTTPS redirection
$redirect = Get-WebConfigurationProperty -Filter "system.webServer/httpRedirect" -Name "enabled" -PSPath $SitePath
$results["https_redirect"] = $redirect.Value

# Check for HSTS header
$hsts = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.webServer/httpProtocol/customHeaders" -name "." |
         Where-Object { $_.name -eq "Strict-Transport-Security" }
$results["hsts"] = if ($hsts) { "Enabled" } else { "Missing" }

# Check if directory browsing is disabled
$dirBrowsing = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/directoryBrowse" -name "enabled"
$results["directory_browsing"] = $dirBrowsing.Value

# Check where IIS logs are saved
$logPath = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory"
$results["log_path"] = $logPath

# Check security headers
$headers = @("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy")
foreach ($h in $headers) {
    $val = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpProtocol/customHeaders" -name "." |
           Where-Object { $_.name -eq $h }
    $results["header_$h"] = if ($val) { $val.value } else { "Missing" }
}

# Check if X-Powered-By is exposed
$xPoweredBy = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpProtocol/customHeaders" -name "." |
              Where-Object { $_.name -eq "X-Powered-By" }
$results["header_X-Powered-By"] = if ($xPoweredBy) { "Present (Remove it!)" } else { "Not present" }

# Check if TLS 1.2 is enabled (Registry)
$tls12 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue
$results["tls_1_2_enabled"] = if ($tls12.Enabled -eq 1) { "Yes" } else { "No or Not Enforced" }

# Check if TLS 1.0 is still enabled
$tls10 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name "Enabled" -ErrorAction SilentlyContinue
$results["tls_1_0_enabled"] = if ($tls10.Enabled -eq 1) { "Yes (Disable It!)" } else { "No" }

# ====== NEW WEB.CONFIG FILE SECURITY CHECKS ======

# Find all web.config files under common locations
$webConfigs = Get-ChildItem -Path "C:\inetpub\wwwroot" -Recurse -Filter "web.config" -ErrorAction SilentlyContinue

$results["webconfig_checks"] = @()

foreach ($config in $webConfigs) {
    try {
        [xml]$xml = Get-Content $config.FullName

        $check = @{
            path = $config.FullName
            requireSSL = $false
            httpOnlyCookies = $false
            customErrors = $false
            requestFiltering = $false
        }

        # Check <system.web> settings
        if ($xml.configuration.'system.web') {
            if ($xml.configuration.'system.web'.authentication.Forms.requireSSL -eq "true") {
                $check.requireSSL = $true
            }
            if ($xml.configuration.'system.web'.httpCookies.httpOnlyCookies -eq "true") {
                $check.httpOnlyCookies = $true
            }
            if ($xml.configuration.'system.web'.customErrors.mode -eq "On") {
                $check.customErrors = $true
            }
        }

        # Check <system.webServer> request filtering
        if ($xml.configuration.'system.webServer'.security.requestFiltering) {
            $check.requestFiltering = $true
        }

        $results["webconfig_checks"] += $check
    }
    catch {
        Write-Warning "Failed to parse $($config.FullName): $_"
    }
}

# ===== NEW: applicationHost.config ACL Check =====
try {
    $configPath = "$env:windir\System32\inetsrv\config\applicationHost.config"
    $acl = Get-Acl $configPath

    $results["applicationHost_config_acl"] = @()

    foreach ($entry in $acl.Access) {
        $results["applicationHost_config_acl"] += @{
            IdentityReference = $entry.IdentityReference.ToString()
            FileSystemRights  = $entry.FileSystemRights.ToString()
            AccessControlType = $entry.AccessControlType.ToString()
        }
    }
} catch {
    $results["applicationHost_config_acl_error"] = $_.Exception.Message
}


# ===== IIS Logging Enabled Check =====
try {
    $logConfig = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/logFile" -PSPath $SitePath -Name "logFormat"
    $logEnabled = if ($logConfig) { "Enabled" } else { "Disabled or not configured" }
    $results["iis_logging_status"] = $logEnabled
} catch {
    $results["iis_logging_status"] = "Error retrieving logging status: $_"
}


# ====== SAVE RESULTS ======

$results | ConvertTo-Json -Depth 6 | Out-File -FilePath "$OutDir/iis_report.json"
