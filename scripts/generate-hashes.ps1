# generate-hashes.ps1
# Generates version-hashes.json from the sitecore fingerprint files in data/sitecore/.
# Run this script whenever new Sitecore version files are added to data/sitecore/.

param (
    [string]$SourcePath = (Join-Path $PSScriptRoot "..\data\sitecore"),
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\chrome-extension\data\version-hashes.json")
)

$Files = @("webedit.css", "default.css", "default.js")

function Get-SHA256Hash {
    param ([string]$Path)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $hashBytes = $sha256.ComputeHash($stream)
            return ($hashBytes | ForEach-Object { $_.ToString("X2") }) -join ""
        } finally {
            $stream.Close()
        }
    } finally {
        $sha256.Dispose()
    }
}

# Initialize per-file hash lookups
$FileHashes = @{}
foreach ($File in $Files) {
    $FileHashes[$File] = @{}
}

# Composite hash lookup
$Composites = @{}

# Walk all version directories (leaf directories containing the actual files)
$VersionDirs = Get-ChildItem -Path $SourcePath -Recurse -Directory |
    Where-Object {
        $HasFiles = Get-ChildItem -Path $_.FullName -File | Where-Object { $Files -contains $_.Name }
        $HasFiles.Count -gt 0
    }

$VersionCount = 0

foreach ($VersionDir in $VersionDirs) {
    $VersionName = $VersionDir.Name -Replace "^Sitecore\s*", ""
    $VersionName = $VersionName.Trim()
    $CompositeHash = ""

    foreach ($File in $Files) {
        $FilePath = Join-Path $VersionDir.FullName $File
        if (Test-Path $FilePath) {
            $Hash = Get-SHA256Hash -Path $FilePath

            # Per-file lookup: hash -> [version names]
            if (-not $FileHashes[$File].ContainsKey($Hash)) {
                $FileHashes[$File][$Hash] = @()
            }
            $FileHashes[$File][$Hash] += $VersionName

            $CompositeHash += $File + $Hash
        }
    }

    if ($CompositeHash -ne "") {
        if (-not $Composites.ContainsKey($CompositeHash)) {
            $Composites[$CompositeHash] = @()
        }
        $Composites[$CompositeHash] += $VersionName
        $VersionCount++
    }
}

# Build output structure
$Output = @{
    files = $FileHashes
    composites = $Composites
}

# Ensure output directory exists
$OutputDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$Json = $Output | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($OutputPath, $Json, [System.Text.UTF8Encoding]::new($false))

Write-Host "Generated: $OutputPath"
Write-Host "  Versions processed: $VersionCount"
Write-Host "  Composite entries: $($Composites.Count)"
