param (
    [string]$OutDir = "./output"
)

try {
    $tempPath = Join-Path $env:TEMP "secpol.inf"

    secedit /export /cfg $tempPath | Out-Null

    $parsed = @{}

    $content = Get-Content $tempPath

    foreach ($line in $content) {
        if ($line -match "^LockoutBadCount\s*=\s*(\d+)") {
            $parsed["LockoutThreshold"] = if ($matches[1] -ne "0") { $matches[1] } else { "Not Configured" }
        }
        if ($line -match "^ResetLockoutCount\s*=\s*(\d+)") {
            $parsed["LockoutObservationWindowMinutes"] = if ($matches[1] -ne "0") { $matches[1] } else { "Not Configured" }
        }
        if ($line -match "^LockoutDuration\s*=\s*(\d+)") {
            $parsed["LockoutDurationMinutes"] = if ($matches[1] -ne "0") { $matches[1] } else { "Not Configured" }
        }
    }

    if ($parsed.Count -eq 0) {
        $parsed["error"] = "Could not parse security policy. Check manually."
    }

    $parsed | ConvertTo-Json | Out-File (Join-Path $OutDir "account_lockout_summary.json")
    Write-Host "[+] Account lockout policy collected."

    # Clean up
    Remove-Item $tempPath -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Account lockout check failed: $_"
}
