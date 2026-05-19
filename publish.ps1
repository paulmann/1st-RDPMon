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
	$found = [System.Collections.Generic.List[pscustomobject]]::new()

	foreach ($name in $candidates) {
		$procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
		foreach ($proc in $procs) {
			if ($null -eq $proc) { continue }

			# Read all properties defensively inside ONE try/catch so a process that
			# exited mid-iteration (or whose MainModule is inaccessible) never produces
			# a half-built pscustomobject. Format-Table under StrictMode rejects items
			# whose declared property is missing — building objects atomically prevents
			# that failure mode.
			$procName = $null
			$procId = $null
			$procPath = $null
			try {
				$procName = [string]$proc.ProcessName
				$procId = [int]$proc.Id
				try { $procPath = [string]$proc.Path } catch { $procPath = $null }
			} catch {
				Write-Verbose ("Skipping inaccessible {0} process (PID query failed): {1}" -f $name, $_.Exception.Message)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($procPath)) { continue }

			$fullProcPath = $null
			try { $fullProcPath = [System.IO.Path]::GetFullPath($procPath) } catch { $fullProcPath = $null }
			if ([string]::IsNullOrWhiteSpace($fullProcPath)) { continue }

			if ($fullProcPath.StartsWith($normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
				$entry = [pscustomobject]@{
					ProcessName = $procName
					Id          = $procId
					ExePath     = $fullProcPath
				}
				$found.Add($entry)
			}
		}
	}

	return ,$found.ToArray()
}

function Format-LockingProcess {
	param([Parameter(Mandatory = $true)]$Item)
	$name = if ($Item.PSObject.Properties['ProcessName']) { $Item.ProcessName } else { '<unknown>' }
	$id = if ($Item.PSObject.Properties['Id']) { $Item.Id } else { '?' }
	$path = if ($Item.PSObject.Properties['ExePath']) { $Item.ExePath } else { '<unknown path>' }
	return ("{0} (PID {1}) -> {2}" -f $name, $id, $path)
}

function Remove-PublishOutput {
	param([Parameter(Mandatory = $true)][string]$Path)

	if (-not (Test-Path $Path)) { return }

	$locking = @(Get-ProcessesUsingPath -Path $Path)
	if ($locking.Count -gt 0) {
		Write-Host "The following RdpAudit processes are running from the publish folder and will block deletion:" -ForegroundColor Yellow
		foreach ($entry in $locking) {
			Write-Host ("  " + (Format-LockingProcess -Item $entry)) -ForegroundColor Yellow
		}
		if ($Force) {
			foreach ($p in $locking) {
				$pName = if ($p.PSObject.Properties['ProcessName']) { $p.ProcessName } else { '<unknown>' }
				$pId = if ($p.PSObject.Properties['Id']) { $p.Id } else { -1 }
				Write-Host ("Stopping {0} (PID {1}) ..." -f $pName, $pId) -ForegroundColor Yellow
				try {
					if ($pId -ge 0) {
						Stop-Process -Id $pId -Force -ErrorAction Stop
					}
				} catch {
					throw ("Failed to stop {0} (PID {1}): {2}" -f $pName, $pId, $_.Exception.Message)
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
				$hint = ""
				if ($still.Count -gt 0) {
					$descriptions = foreach ($s in $still) { Format-LockingProcess -Item $s }
					$hint = "Still locked by: " + ($descriptions -join "; ")
				} else {
					$hint = "No RdpAudit processes detected from publish; the file may be held by Explorer, an antivirus scanner, or another tool. Close any window or shell open in '$Path' and retry."
				}
				throw ("Unable to remove '{0}' after {1} attempts. {2} Original error: {3}" -f $Path, $maxAttempts, $hint, $_.Exception.Message)
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
