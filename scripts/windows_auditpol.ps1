param (
    [string]$OutDir = "./output"
)

# Make sure output directory exists
if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

# Run auditpol.exe to get all audit categories
$auditSettings = auditpol.exe /get /category:* | Out-String

# Save raw output
$auditFilePath = Join-Path $OutDir "windows_auditpol.txt"
$auditSettings | Out-File -FilePath $auditFilePath

# Parse key audit categories for summary if needed
$auditSummary = @{}

$auditSettings -split "`r?`n" | ForEach-Object {
    if ($_ -match "^(\S.*?)\s+Success\s+Failure$") {
        $auditSummary[$matches[1]] = "Success and Failure"
    }
    elseif ($_ -match "^(\S.*?)\s+Success$") {
        $auditSummary[$matches[1]] = "Success Only"
    }
    elseif ($_ -match "^(\S.*?)\s+Failure$") {
        $auditSummary[$matches[1]] = "Failure Only"
    }
    elseif ($_ -match "^(\S.*?)\s+No Auditing$") {
        $auditSummary[$matches[1]] = "No Auditing"
    }
}

# Save parsed audit summary
$auditSummary | ConvertTo-Json -Depth 3 | Out-File -FilePath (Join-Path $OutDir "windows_audit_summary.json")

Write-Host "[+] Windows audit policy collected."
