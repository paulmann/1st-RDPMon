# File:    publish.ps1
# Module:  RdpAudit build orchestration
# Purpose: Publishes RdpAudit.Service and RdpAudit.Configurator as self-contained
#          single-file executables for win-x64. Detects publish-output files that
#          are locked by running RdpAudit processes (typical when the user has
#          just been testing locally) and emits a clear, actionable diagnostic
#          instead of failing with an opaque Remove-Item error.
# Author:  Mikhail Deynekin
# Site:    https://Deynekin.com
# Requires PowerShell 7+

param(
	[string]$Version = "1.0.0",
	[string]$Configuration = "Release",
	[switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$publishRoot = Join-Path $PSScriptRoot "publish"

function Get-ProcessesUsingPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	$normalized = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
	$candidates = @("RdpAudit.Configurator", "RdpAudit.Service")
	$found = @()

	foreach ($name in $candidates) {
		$procs = Get-Process -Name $name -ErrorAction SilentlyContinue
		foreach ($proc in $procs) {
			$procPath = $null
			try { $procPath = $proc.Path } catch { $procPath = $null }
			if (-not $procPath) { continue }
			$fullProcPath = [System.IO.Path]::GetFullPath($procPath)
			if ($fullProcPath.StartsWith($normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
				$found += [pscustomobject]@{
					ProcessName = $proc.ProcessName
					Id          = $proc.Id
					ExePath     = $fullProcPath
				}
			}
		}
	}

	return ,$found
}

function Remove-PublishOutput {
	param([Parameter(Mandatory = $true)][string]$Path)

	if (-not (Test-Path $Path)) { return }

	$locking = @(Get-ProcessesUsingPath -Path $Path)
	if ($locking.Count -gt 0) {
		Write-Host "The following RdpAudit processes are running from the publish folder and will block deletion:" -ForegroundColor Yellow
		$locking | Format-Table ProcessName, Id, ExePath -AutoSize | Out-Host
		if ($Force) {
			foreach ($p in $locking) {
				Write-Host "Stopping $($p.ProcessName) (PID $($p.Id)) ..." -ForegroundColor Yellow
				try {
					Stop-Process -Id $p.Id -Force -ErrorAction Stop
				} catch {
					throw "Failed to stop $($p.ProcessName) (PID $($p.Id)): $($_.Exception.Message)"
				}
			}
			Start-Sleep -Milliseconds 500
		} else {
			throw "Publish output is in use by running RdpAudit processes. Close the Configurator (and stop the service if installed) and retry, or re-run with -Force to terminate them automatically."
		}
	}

	$attempts = 0
	$maxAttempts = 5
	while ($true) {
		$attempts++
		try {
			Remove-Item -Recurse -Force $Path -ErrorAction Stop
			return
		} catch {
			if ($attempts -ge $maxAttempts) {
				$still = @(Get-ProcessesUsingPath -Path $Path)
				$hint = if ($still.Count -gt 0) {
					"Still locked by: " + (($still | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ", ")
				} else {
					"No RdpAudit processes detected from publish; the file may be held by Explorer, an antivirus scanner, or another tool. Close any window or shell open in '$Path' and retry."
				}
				throw "Unable to remove '$Path' after $maxAttempts attempts. $hint Original error: $($_.Exception.Message)"
			}
			Start-Sleep -Milliseconds (250 * $attempts)
		}
	}
}

function Publish-Project {
	param(
		[Parameter(Mandatory = $true)][string]$Project,
		[Parameter(Mandatory = $true)][string]$Subdir
	)

	$target = Join-Path $publishRoot $Subdir
	Write-Host "Publishing $Project -> $target" -ForegroundColor Cyan

	dotnet publish $Project `
		-c $Configuration `
		-r win-x64 `
		--self-contained true `
		-p:PublishSingleFile=true `
		-p:IncludeNativeLibrariesForSelfExtract=true `
		-p:EnableCompressionInSingleFile=true `
		-p:VersionPrefix=$Version `
		-o $target

	if ($LASTEXITCODE -ne 0) {
		throw "publish failed: $Project (exit $LASTEXITCODE)"
	}
}

Remove-PublishOutput -Path $publishRoot

Publish-Project -Project "src/RdpAudit.Service/RdpAudit.Service.csproj"           -Subdir "Service"
Publish-Project -Project "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj" -Subdir "Configurator"

Write-Host "Done -> $publishRoot" -ForegroundColor Green
