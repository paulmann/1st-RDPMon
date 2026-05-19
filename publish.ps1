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
#
# Notes on variable naming:
#   `$PID` is a PowerShell automatic, read-only variable holding the current
#   process id. PowerShell variable names are case-insensitive, so `$pId`,
#   `$Pid`, `$pid` ALL refer to that same read-only automatic. Any assignment
#   to those names raises:
#     "Cannot overwrite variable PID because it is read-only or constant."
#   All process-id locals in this script use `$processIdValue` to avoid the
#   collision. Do not introduce new variables whose lowercase spelling is
#   `pid` -- the parser will not catch this; it surfaces only at runtime.

[CmdletBinding()]
param(
	[string]$Version = "1.0.0",
	[string]$Configuration = "Release",
	[switch]$Force
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$publishRoot = Join-Path $PSScriptRoot "publish"

# -----------------------------------------------------------------------------
# Diagnostic plumbing
# -----------------------------------------------------------------------------
# Collected during process inspection so that the eventual failure message
# (if any) can tell the user exactly what we could and could not see.
$script:InspectionFailures = [System.Collections.Generic.List[pscustomobject]]::new()

function Write-Diag {
	param([Parameter(Mandatory = $true)][string]$Message)
	Write-Verbose $Message
}

function Add-InspectionFailure {
	param(
		[Parameter(Mandatory = $true)][string]$ProcessName,
		[Nullable[int]]$ProcessIdValue,
		[Parameter(Mandatory = $true)][string]$Reason
	)
	$entry = [pscustomobject]@{
		ProcessName    = $ProcessName
		ProcessIdValue = $ProcessIdValue
		Reason         = $Reason
	}
	$script:InspectionFailures.Add($entry)
	$idText = if ($null -ne $ProcessIdValue) { $ProcessIdValue.ToString() } else { '?' }
	Write-Diag ("Inspection failure: {0} (PID {1}) -> {2}" -f $ProcessName, $idText, $Reason)
}

# -----------------------------------------------------------------------------
# Process discovery
# -----------------------------------------------------------------------------
# Returns ONLY processes for which we have strong evidence (a readable
# executable path) that they are running from the target folder. Processes
# whose path cannot be read are recorded as inspection failures instead --
# they are never reported as blockers and are never killed under -Force.
function Get-ProcessesUsingPath {
	param([Parameter(Mandatory = $true)][string]$Path)

	$normalized = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
	$candidates = @("RdpAudit.Configurator", "RdpAudit.Service")
	$found = [System.Collections.Generic.List[pscustomobject]]::new()

	foreach ($name in $candidates) {
		$procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
		Write-Diag ("Found {0} '{1}' process(es)" -f $procs.Count, $name)

		foreach ($proc in $procs) {
			if ($null -eq $proc) { continue }

			# Read identity defensively. If even Id/Name fail, the process
			# exited or is otherwise inaccessible -- record and skip.
			$procName = $null
			$processIdValue = $null
			try {
				$procName = [string]$proc.ProcessName
				$processIdValue = [int]$proc.Id
			} catch {
				Add-InspectionFailure -ProcessName $name -ProcessIdValue $null `
					-Reason ("could not read identity: " + $_.Exception.Message)
				continue
			}

			# Read path inside its own try -- this is the property that most
			# commonly throws (access denied, exited process, native error).
			$procPath = $null
			$pathReadError = $null
			try {
				$procPath = [string]$proc.Path
			} catch {
				$pathReadError = $_.Exception.Message
			}

			if ($null -ne $pathReadError) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason ("could not read executable path: " + $pathReadError)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($procPath)) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason "executable path was empty"
				continue
			}

			$fullProcPath = $null
			try {
				$fullProcPath = [System.IO.Path]::GetFullPath($procPath)
			} catch {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason ("could not normalize path '$procPath': " + $_.Exception.Message)
				continue
			}

			if ([string]::IsNullOrWhiteSpace($fullProcPath)) {
				Add-InspectionFailure -ProcessName $procName -ProcessIdValue $processIdValue `
					-Reason "normalized path was empty"
				continue
			}

			if (-not $fullProcPath.StartsWith($normalized, [System.StringComparison]::OrdinalIgnoreCase)) {
				Write-Diag ("Skipping {0} (PID {1}) -> {2}: outside publish root" -f $procName, $processIdValue, $fullProcPath)
				continue
			}

			$entry = [pscustomobject]@{
				ProcessName    = $procName
				ProcessIdValue = $processIdValue
				ExePath        = $fullProcPath
			}
			$found.Add($entry)
			Write-Diag ("Blocker confirmed: {0} (PID {1}) -> {2}" -f $procName, $processIdValue, $fullProcPath)
		}
	}

	return ,$found.ToArray()
}

function Format-LockingProcess {
	param([Parameter(Mandatory = $true)]$Item)
	return ("{0} (PID {1}) -> {2}" -f $Item.ProcessName, $Item.ProcessIdValue, $Item.ExePath)
}

function Format-InspectionFailure {
	param([Parameter(Mandatory = $true)]$Item)
	$idText = if ($null -ne $Item.ProcessIdValue) { $Item.ProcessIdValue.ToString() } else { '?' }
	return ("{0} (PID {1}): {2}" -f $Item.ProcessName, $idText, $Item.Reason)
}

function Write-InspectionDiagnostics {
	if ($script:InspectionFailures.Count -eq 0) { return }
	Write-Host "" -ForegroundColor DarkGray
	Write-Host "Unable to inspect the following process(es) (NOT classified as blockers):" -ForegroundColor DarkYellow
	foreach ($f in $script:InspectionFailures) {
		Write-Host ("  " + (Format-InspectionFailure -Item $f)) -ForegroundColor DarkYellow
	}
	Write-Host "Hint: run this script from an elevated PowerShell to read process paths." -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# Removal with actionable diagnostics
# -----------------------------------------------------------------------------
function Remove-PublishOutput {
	param([Parameter(Mandatory = $true)][string]$Path)

	if (-not (Test-Path $Path)) {
		Write-Diag "Publish output path does not exist; nothing to remove: $Path"
		return
	}

	$script:InspectionFailures.Clear()
	$locking = @(Get-ProcessesUsingPath -Path $Path)

	if ($locking.Count -gt 0) {
		Write-Host "The following RdpAudit processes are running from the publish folder and will block deletion:" -ForegroundColor Yellow
		foreach ($entry in $locking) {
			Write-Host ("  " + (Format-LockingProcess -Item $entry)) -ForegroundColor Yellow
		}
		Write-InspectionDiagnostics

		if ($Force) {
			foreach ($p in $locking) {
				$pName = $p.ProcessName
				$processIdValue = $p.ProcessIdValue
				Write-Host ("Stopping {0} (PID {1}) ..." -f $pName, $processIdValue) -ForegroundColor Yellow
				try {
					Stop-Process -Id $processIdValue -Force -ErrorAction Stop
				} catch {
					throw (Format-RemoveFailure -Path $Path -ExtraContext (
						"Failed to stop {0} (PID {1}): {2} ({3})" -f `
							$pName, $processIdValue, $_.Exception.Message, $_.Exception.GetType().FullName))
				}
			}
			Start-Sleep -Milliseconds 500
		} else {
			throw (Format-RemoveFailure -Path $Path -ExtraContext (
				"Detected " + $locking.Count + " RdpAudit process(es) running from the publish folder. " +
				"Close the Configurator (and stop the service if installed) and retry, " +
				"or re-run with -Force to terminate them automatically."))
		}
	} else {
		# No confirmed blockers, but we still want the user to see inspection
		# failures (if any) so they know detection was best-effort.
		Write-InspectionDiagnostics
	}

	$attempts = 0
	$maxAttempts = 5
	$lastError = $null
	while ($true) {
		$attempts++
		try {
			Write-Diag ("Removing '{0}' (attempt {1}/{2})" -f $Path, $attempts, $maxAttempts)
			Remove-Item -Recurse -Force $Path -ErrorAction Stop
			return
		} catch {
			$lastError = $_
			if ($attempts -ge $maxAttempts) {
				$script:InspectionFailures.Clear()
				$still = @(Get-ProcessesUsingPath -Path $Path)
				throw (Format-RemoveFailure `
					-Path $Path `
					-Attempts $attempts `
					-StillLocking $still `
					-OriginalException $lastError.Exception)
			}
			Write-Diag ("Remove-Item attempt {0} failed: {1}" -f $attempts, $_.Exception.Message)
			Start-Sleep -Milliseconds (250 * $attempts)
		}
	}
}

function Format-RemoveFailure {
	param(
		[Parameter(Mandatory = $true)][string]$Path,
		[int]$Attempts = 0,
		[object[]]$StillLocking = @(),
		[System.Exception]$OriginalException = $null,
		[string]$ExtraContext = $null
	)

	$sb = [System.Text.StringBuilder]::new()
	[void]$sb.AppendLine("Unable to clean publish output.")
	[void]$sb.AppendLine("  Target path : $Path")
	if ($Attempts -gt 0) {
		[void]$sb.AppendLine("  Attempts    : $Attempts")
	}

	if ($null -ne $StillLocking -and $StillLocking.Count -gt 0) {
		[void]$sb.AppendLine("  Confirmed RdpAudit blockers still running from the folder:")
		foreach ($s in $StillLocking) {
			[void]$sb.AppendLine("    " + (Format-LockingProcess -Item $s))
		}
	} else {
		[void]$sb.AppendLine("  Confirmed RdpAudit blockers: none detected.")
	}

	if ($script:InspectionFailures.Count -gt 0) {
		[void]$sb.AppendLine("  Processes we could not inspect (NOT confirmed as blockers):")
		foreach ($f in $script:InspectionFailures) {
			[void]$sb.AppendLine("    " + (Format-InspectionFailure -Item $f))
		}
	}

	if ($null -ne $OriginalException) {
		[void]$sb.AppendLine("  Underlying error:")
		[void]$sb.AppendLine("    Type    : " + $OriginalException.GetType().FullName)
		[void]$sb.AppendLine("    Message : " + $OriginalException.Message)
		# IOException carries a target file name on Windows for locked files.
		try {
			$targetFile = $OriginalException.PSObject.Properties['FileName']
			if ($null -ne $targetFile -and $null -ne $targetFile.Value) {
				[void]$sb.AppendLine("    File    : " + $targetFile.Value)
			}
		} catch {
			# best-effort only
		}
	}

	if (-not [string]::IsNullOrWhiteSpace($ExtraContext)) {
		[void]$sb.AppendLine("  Context     : $ExtraContext")
	}

	[void]$sb.AppendLine("  Likely causes:")
	[void]$sb.AppendLine("    - RdpAudit.Configurator window is still open.")
	[void]$sb.AppendLine("    - The installed RdpAudit service is running (locks Service\\*.exe).")
	[void]$sb.AppendLine("    - An Explorer window or terminal has the publish folder open.")
	[void]$sb.AppendLine("    - Antivirus / EDR is scanning the freshly written binaries.")
	[void]$sb.AppendLine("    - A previous publish left a stale handle; reboot resolves it.")
	[void]$sb.AppendLine("  Next steps:")
	[void]$sb.AppendLine("    1. Close Configurator: taskkill /IM RdpAudit.Configurator.exe /F")
	[void]$sb.AppendLine("    2. Stop the service (if installed): sc.exe stop RdpAudit")
	[void]$sb.AppendLine("    3. Close any Explorer/terminal pointing at '$Path'.")
	[void]$sb.AppendLine("    4. Re-run:  pwsh -NoProfile -File .\\publish.ps1 -Force -Verbose")

	return $sb.ToString().TrimEnd()
}

# -----------------------------------------------------------------------------
# Publish
# -----------------------------------------------------------------------------
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
