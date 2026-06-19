#Requires -Version 7.0
<#
.SYNOPSIS
	RdpAudit prerequisite checker and full installation script.

.DESCRIPTION
	Checks all required prerequisites, prints installed versions, offers to install
	missing components through winget, re-checks the environment, downloads the
	RdpAudit source tree, patches vulnerable package references, restores NuGet
	packages, builds Release, runs tests, publishes binaries and launches the
	Configurator executable.

.NOTES
	Author : Mikhail Deynekin — https://Deynekin.com — Mikhail@Deynekin.com
	Version: 1.1.0

.REQUIREMENTS
	PowerShell 7+
	Windows
	Administrator session
	Git
	.NET SDK 8+
	winget for automatic prerequisite installation
#>

[CmdletBinding()]
param(
	[string]$WorkDirectory = 'C:\1st_RdpMON',

	[string]$RepositoryUrl = 'https://github.com/paulmann/1st-RDPMon.git',

	[string]$RepositoryBranch = 'feat/rdpaudit-implementation',

	[string]$SafeMessagePackVersion = '2.5.301',

	[switch]$NonInteractive,

	[switch]$SkipLaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ── Fields & Configuration ───────────────────────────────────────────────────

$script:RepositoryDirectory = Join-Path -Path $WorkDirectory -ChildPath 'Service'
$script:SolutionPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'RdpAudit.sln'
$script:PublishScriptPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish.ps1'
$script:ConfiguratorPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'publish\Configurator\RdpAudit.Configurator.exe'
$script:MinimumDotNetSdkVersion = [Version]'8.0'
$script:RequiredComponents = @('PowerShell 7+', 'Windows', 'Administrator', 'Git', '.NET SDK 8+')

# ── Console Output ───────────────────────────────────────────────────────────

function Write-Section {
	param(
		[Parameter(Mandatory)]
		[string]$Title
	)

	$line = '─' * 78
	Write-Host ''
	Write-Host $line -ForegroundColor Cyan
	Write-Host " $Title" -ForegroundColor Cyan
	Write-Host $line -ForegroundColor Cyan
}

function Write-Ok {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [OK]  $Message" -ForegroundColor Green
}

function Write-Info {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [..]  $Message" -ForegroundColor Gray
}

function Write-WarningMessage {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [!!]  $Message" -ForegroundColor Yellow
}

function Write-ErrorMessage {
	param([Parameter(Mandatory)][string]$Message)
	Write-Host " [XX]  $Message" -ForegroundColor Red
}

# ── Version & Environment Helpers ────────────────────────────────────────────

function ConvertTo-VersionOrNull {
	param(
		[AllowNull()]
		[string]$Value
	)

	if ([string]::IsNullOrWhiteSpace($Value)) {
		return $null
	}

	$match = [regex]::Match($Value, '\d+(\.\d+){1,3}')
	if (-not $match.Success) {
		return $null
	}

	try {
		return [Version]$match.Value
	} catch {
		return $null
	}
}

function Test-IsAdministrator {
	if (-not $IsWindows) {
		return $false
	}

	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	$principal = [Security.Principal.WindowsPrincipal]::new($identity)

	return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-CommandVersionText {
	param(
		[Parameter(Mandatory)]
		[string]$CommandName,

		[Parameter(Mandatory)]
		[string[]]$Arguments
	)

	$command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
	if ($null -eq $command) {
		return $null
	}

	try {
		$output = & $CommandName @Arguments 2>$null
		if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
			return $null
		}

		$text = ($output | Select-Object -First 1)
		if ([string]::IsNullOrWhiteSpace($text)) {
			return $null
		}

		return [string]$text
	} catch {
		return $null
	}
}

function Get-DotNetSdkInfo {
	$dotnetCommand = Get-Command -Name 'dotnet' -ErrorAction SilentlyContinue
	if ($null -eq $dotnetCommand) {
		return [pscustomobject]@{
			IsInstalled = $false
			DisplayText = 'NOT FOUND'
			BestVersion = $null
			AllVersions = @()
		}
	}

	$versions = @()

	try {
		$rawSdks = @(dotnet --list-sdks 2>$null)
		foreach ($sdkLine in $rawSdks) {
			$version = ConvertTo-VersionOrNull -Value $sdkLine
			if ($null -ne $version) {
				$versions += $version
			}
		}
	} catch {
		$versions = @()
	}

	if ($versions.Count -eq 0) {
		$singleVersionText = Get-CommandVersionText -CommandName 'dotnet' -Arguments @('--version')
		$singleVersion = ConvertTo-VersionOrNull -Value $singleVersionText
		if ($null -ne $singleVersion) {
			$versions += $singleVersion
		}
	}

	if ($versions.Count -eq 0) {
		return [pscustomobject]@{
			IsInstalled = $false
			DisplayText = 'NOT FOUND'
			BestVersion = $null
			AllVersions = @()
		}
	}

	$bestVersion = $versions | Sort-Object -Descending | Select-Object -First 1
	$displayText = (($versions | Sort-Object -Descending | ForEach-Object { $_.ToString() }) -join ', ')

	return [pscustomobject]@{
		IsInstalled = $true
		DisplayText = $displayText
		BestVersion = $bestVersion
		AllVersions = $versions
	}
}

function New-PrerequisiteRecord {
	param(
		[Parameter(Mandatory)]
		[string]$Name,

		[Parameter(Mandatory)]
		[string]$Required,

		[Parameter(Mandatory)]
		[string]$Installed,

		[Parameter(Mandatory)]
		[bool]$IsSatisfied,

		[Parameter(Mandatory)]
		[bool]$IsMandatory,

		[AllowNull()]
		[string]$WingetId
	)

	return [pscustomobject]@{
		Name = $Name
		Required = $Required
		Installed = $Installed
		Status = if ($IsSatisfied) { 'OK' } else { 'MISSING' }
		IsSatisfied = $IsSatisfied
		IsMandatory = $IsMandatory
		WingetId = $WingetId
	}
}

# ── Prerequisite Checks ──────────────────────────────────────────────────────

function Get-PrerequisiteStatus {
	$items = @()

	$psVersion = $PSVersionTable.PSVersion
	$items += New-PrerequisiteRecord `
		-Name 'PowerShell 7+' `
		-Required '7.0+' `
		-Installed $psVersion.ToString() `
		-IsSatisfied ($psVersion.Major -ge 7) `
		-IsMandatory $true `
		-WingetId 'Microsoft.PowerShell'

	$windowsText = if ($IsWindows) { [System.Environment]::OSVersion.VersionString } else { 'NOT WINDOWS' }
	$items += New-PrerequisiteRecord `
		-Name 'Windows' `
		-Required 'Windows OS' `
		-Installed $windowsText `
		-IsSatisfied $IsWindows `
		-IsMandatory $true `
		-WingetId $null

	$isAdmin = Test-IsAdministrator
	$adminText = if ($isAdmin) { 'Elevated' } else { 'NOT ELEVATED' }
	$items += New-PrerequisiteRecord `
		-Name 'Administrator' `
		-Required 'Elevated session' `
		-Installed $adminText `
		-IsSatisfied $isAdmin `
		-IsMandatory $true `
		-WingetId $null

	$gitVersionText = Get-CommandVersionText -CommandName 'git' -Arguments @('--version')
	$gitInstalledText = if ([string]::IsNullOrWhiteSpace($gitVersionText)) { 'NOT FOUND' } else { $gitVersionText -replace '^git version\s+', '' }
	$items += New-PrerequisiteRecord `
		-Name 'Git' `
		-Required '2.x+' `
		-Installed $gitInstalledText `
		-IsSatisfied (-not [string]::IsNullOrWhiteSpace($gitVersionText)) `
		-IsMandatory $true `
		-WingetId 'Git.Git'

	$dotNet = Get-DotNetSdkInfo
	$dotNetOk = $false
	if ($dotNet.IsInstalled -and $null -ne $dotNet.BestVersion) {
		$dotNetOk = $dotNet.BestVersion -ge $script:MinimumDotNetSdkVersion
	}

	$items += New-PrerequisiteRecord `
		-Name '.NET SDK 8+' `
		-Required '8.0+' `
		-Installed $dotNet.DisplayText `
		-IsSatisfied $dotNetOk `
		-IsMandatory $true `
		-WingetId 'Microsoft.DotNet.SDK.8'

	$wingetVersionText = Get-CommandVersionText -CommandName 'winget' -Arguments @('--version')
	$wingetInstalledText = if ([string]::IsNullOrWhiteSpace($wingetVersionText)) { 'NOT FOUND' } else { $wingetVersionText }
	$items += New-PrerequisiteRecord `
		-Name 'winget' `
		-Required 'Required only for auto-install' `
		-Installed $wingetInstalledText `
		-IsSatisfied (-not [string]::IsNullOrWhiteSpace($wingetVersionText)) `
		-IsMandatory $false `
		-WingetId $null

	return $items
}

function Show-PrerequisiteStatus {
	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	Write-Section 'Prerequisite Check'

	$format = '{0,-20} {1,-28} {2,-34} {3,-10}'
	Write-Host ($format -f 'Component', 'Required', 'Installed', 'Status') -ForegroundColor White
	Write-Host ($format -f '---------', '--------', '---------', '------') -ForegroundColor DarkGray

	foreach ($item in $Items) {
		$color = if ($item.IsSatisfied) { 'Green' } else { 'Red' }
		Write-Host ($format -f $item.Name, $item.Required, $item.Installed, $item.Status) -ForegroundColor $color
	}

	Write-Host ''
}

function Test-MandatoryPrerequisites {
	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	$missingMandatory = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied })
	return ($missingMandatory.Count -eq 0)
}

# ── User Interaction ─────────────────────────────────────────────────────────

function Confirm-Action {
	param(
		[Parameter(Mandatory)]
		[string]$Prompt,

		[bool]$DefaultYes = $false
	)

	if ($NonInteractive) {
		return $DefaultYes
	}

	$suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
	$answer = Read-Host "$Prompt $suffix"

	if ([string]::IsNullOrWhiteSpace($answer)) {
		return $DefaultYes
	}

	return ($answer -match '^(y|yes)$')
}

# ── External Process Runner ──────────────────────────────────────────────────

function Invoke-CheckedCommand {
	param(
		[Parameter(Mandatory)]
		[string]$FilePath,

		[Parameter(Mandatory)]
		[string[]]$Arguments,

		[Parameter(Mandatory)]
		[string]$FailureMessage,

		[string]$WorkingDirectory
	)

	$previousLocation = Get-Location

	try {
		if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
			Set-Location -Path $WorkingDirectory
		}

		Write-Info ("Running: {0} {1}" -f $FilePath, ($Arguments -join ' '))
		& $FilePath @Arguments

		if ($LASTEXITCODE -ne 0) {
			throw "$FailureMessage Exit code: $LASTEXITCODE."
		}
	} finally {
		Set-Location -Path $previousLocation
	}
}

# ── Auto Installation ────────────────────────────────────────────────────────

function Install-MissingPrerequisites {
	param(
		[Parameter(Mandatory)]
		[object[]]$Items
	)

	$missingInstallable = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied -and -not [string]::IsNullOrWhiteSpace($_.WingetId) })
	$missingManual = @($Items | Where-Object { $_.IsMandatory -and -not $_.IsSatisfied -and [string]::IsNullOrWhiteSpace($_.WingetId) })

	if ($missingManual.Count -gt 0) {
		Write-Section 'Manual Requirements'
		foreach ($item in $missingManual) {
			Write-ErrorMessage "$($item.Name) is required and cannot be installed automatically by this script."
		}

		return $false
	}

	if ($missingInstallable.Count -eq 0) {
		Write-Ok 'No installable prerequisites are missing.'
		return $true
	}

	$wingetAvailable = $false
	$wingetRecord = $Items | Where-Object { $_.Name -eq 'winget' } | Select-Object -First 1
	if ($null -ne $wingetRecord -and $wingetRecord.IsSatisfied) {
		$wingetAvailable = $true
	}

	if (-not $wingetAvailable) {
		Write-ErrorMessage 'winget is not available. Install missing prerequisites manually, then run this script again.'
		return $false
	}

	Write-Section 'Missing Prerequisites'

	foreach ($item in $missingInstallable) {
		Write-WarningMessage "$($item.Name) is missing. winget id: $($item.WingetId)"
	}

	$installNow = Confirm-Action -Prompt 'Install missing prerequisites now?' -DefaultYes $false
	if (-not $installNow) {
		Write-Info 'Installation cancelled by user.'
		return $false
	}

	foreach ($item in $missingInstallable) {
		Write-Info "Installing $($item.Name) ..."
		Invoke-CheckedCommand `
			-FilePath 'winget' `
			-Arguments @(
				'install',
				'--id', $item.WingetId,
				'--exact',
				'--silent',
				'--accept-source-agreements',
				'--accept-package-agreements'
			) `
			-FailureMessage "winget failed to install $($item.Name)."
		Write-Ok "$($item.Name) installation command completed."
	}

	$machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
	$userPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
	$env:Path = "$machinePath;$userPath"

	return $true
}

# ── Repository Operations ────────────────────────────────────────────────────

function Initialize-Workspace {
	Write-Section 'Workspace'

	if (-not (Test-Path -Path $WorkDirectory)) {
		Write-Info "Creating working directory: $WorkDirectory"
		New-Item -ItemType Directory -Force -Path $WorkDirectory | Out-Null
	} else {
		Write-Ok "Working directory exists: $WorkDirectory"
	}

	if (Test-Path -Path $script:RepositoryDirectory) {
		$gitDirectory = Join-Path -Path $script:RepositoryDirectory -ChildPath '.git'

		if (-not (Test-Path -Path $gitDirectory)) {
			$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
			$backupPath = "$($script:RepositoryDirectory).backup-$timestamp"
			Write-WarningMessage "Existing non-git directory found. Moving it to: $backupPath"
			Move-Item -Path $script:RepositoryDirectory -Destination $backupPath -Force
		}
	}
}

function Sync-Repository {
	Write-Section 'Repository'

	if (-not (Test-Path -Path (Join-Path -Path $script:RepositoryDirectory -ChildPath '.git'))) {
		Write-Info "Cloning $RepositoryBranch from $RepositoryUrl"
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @(
				'clone',
				'--branch', $RepositoryBranch,
				'--single-branch',
				$RepositoryUrl,
				$script:RepositoryDirectory
			) `
			-FailureMessage 'git clone failed.'
	} else {
		Write-Info 'Repository already exists. Fetching and resetting to remote branch.'
		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'fetch', 'origin', $RepositoryBranch) `
			-FailureMessage 'git fetch failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'checkout', $RepositoryBranch) `
			-FailureMessage 'git checkout failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'reset', '--hard', "origin/$RepositoryBranch") `
			-FailureMessage 'git reset failed.'

		Invoke-CheckedCommand `
			-FilePath 'git' `
			-Arguments @('-C', $script:RepositoryDirectory, 'clean', '-fdx') `
			-FailureMessage 'git clean failed.'
	}

	$branch = (& git -C $script:RepositoryDirectory branch --show-current 2>$null | Select-Object -First 1)
	$head = (& git -C $script:RepositoryDirectory log -1 --oneline 2>$null | Select-Object -First 1)

	Write-Ok "Branch: $branch"
	Write-Ok "HEAD  : $head"
}

# ── Package Patch ────────────────────────────────────────────────────────────

function Update-MessagePackPackageReference {
	Write-Section 'Security Patch'

	if (-not (Test-Path -Path $script:RepositoryDirectory)) {
		throw "Repository directory does not exist: $($script:RepositoryDirectory)"
	}

	$projectFiles = @(Get-ChildItem -Path $script:RepositoryDirectory -Filter '*.csproj' -Recurse -File)
	if ($projectFiles.Count -eq 0) {
		throw "No .csproj files found under $($script:RepositoryDirectory)."
	}

	$patchedCount = 0
	$packageReferencePattern = '(<PackageReference\s+Include="MessagePack"\s+Version=")([^"]+)(")'

	foreach ($projectFile in $projectFiles) {
		$content = Get-Content -Path $projectFile.FullName -Raw

		if ($content -notmatch 'Include="MessagePack"') {
			continue
		}

		$updated = [regex]::Replace(
			$content,
			$packageReferencePattern,
			{
				param($match)
				return $match.Groups[1].Value + $SafeMessagePackVersion + $match.Groups[3].Value
			}
		)

		if ($updated -ne $content) {
			Set-Content -Path $projectFile.FullName -Value $updated -NoNewline -Encoding UTF8
			$patchedCount++
			Write-Ok "Patched MessagePack in: $($projectFile.FullName)"
		}
	}

	if ($patchedCount -eq 0) {
		Write-WarningMessage 'No MessagePack package reference was patched. It may already be updated or defined in another format.'
	} else {
		Write-Ok "MessagePack references updated to version $SafeMessagePackVersion."
	}
}

function Set-DotNetSdkGlobalJson {
	Write-Section 'SDK Pin'

	$dotNet = Get-DotNetSdkInfo
	$sdk8Versions = @($dotNet.AllVersions | Where-Object { $_.Major -eq 8 } | Sort-Object -Descending)

	if ($sdk8Versions.Count -eq 0) {
		Write-WarningMessage 'No .NET SDK 8.x version found. Skipping global.json creation.'
		return
	}

	$selectedSdk = $sdk8Versions[0].ToString()
	$globalJsonPath = Join-Path -Path $script:RepositoryDirectory -ChildPath 'global.json'

	$globalJson = [ordered]@{
		sdk = [ordered]@{
			version = $selectedSdk
			rollForward = 'latestFeature'
		}
	}

	$json = $globalJson | ConvertTo-Json -Depth 5
	Set-Content -Path $globalJsonPath -Value $json -Encoding UTF8

	Write-Ok "Pinned .NET SDK via global.json: $selectedSdk"
}

function Test-Ca1859PatchVerification {
	Write-Info 'Verifying CA1859 source patches ...'

	$checks = @(
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'src\RdpAudit.Service\Services\EnforcementReconciliationService.cs'
			Pattern = '\bIReadOnlyList\s*<\s*(?:RdpAudit\.Core\.Models\.)?ActiveBlock\s*>\s+rows\b'
			Description = 'IReadOnlyList<ActiveBlock> rows'
		},
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'tests\RdpAudit.Core.Tests\EventCatalogTests.cs'
			Pattern = '\bIReadOnlyList\s*<\s*string\s*>\s+channels\b'
			Description = 'IReadOnlyList<string> channels'
		}
	)

	foreach ($check in $checks) {
		$content = Get-Content -Path $check.Path -Raw
		if ($content -match $check.Pattern) {
			$lines = Select-String -Path $check.Path -Pattern $check.Pattern
			foreach ($line in $lines) {
				Write-ErrorMessage "Remaining CA1859 pattern in $($check.Path):$($line.LineNumber)"
				Write-Host "       $($line.Line.Trim())" -ForegroundColor DarkRed
			}

			throw "CA1859 verification failed: $($check.Description) still exists."
		}

		Write-Ok "Verified: $($check.Description) is not present."
	}
}

function Update-Ca1859SourceWarnings {
	Write-Section 'Analyzer Patch'

	$patches = @(
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'src\RdpAudit.Service\Services\EnforcementReconciliationService.cs'
			Pattern = '\b(?<prefix>(?:System\.Collections\.Generic\.)?)IReadOnlyList\s*<\s*(?<type>(?:RdpAudit\.Core\.Models\.)?ActiveBlock)\s*>\s+(?<name>rows)\b'
			Replacement = '${prefix}List<${type}> ${name}'
			Description = 'CA1859: replace IReadOnlyList<ActiveBlock> rows with List<ActiveBlock> rows'
		},
		[pscustomobject]@{
			Path = Join-Path -Path $script:RepositoryDirectory -ChildPath 'tests\RdpAudit.Core.Tests\EventCatalogTests.cs'
			Pattern = '\b(?<prefix>(?:System\.Collections\.Generic\.)?)IReadOnlyList\s*<\s*(?<type>string)\s*>\s+(?<name>channels)\b'
			Replacement = '${prefix}List<${type}> ${name}'
			Description = 'CA1859: replace IReadOnlyList<string> channels with List<string> channels'
		}
	)

	foreach ($patch in $patches) {
		if (-not (Test-Path -Path $patch.Path)) {
			throw "CA1859 patch target not found: $($patch.Path)"
		}

		$content = Get-Content -Path $patch.Path -Raw
		$matches = [regex]::Matches($content, $patch.Pattern)

		if ($matches.Count -eq 0) {
			Write-Ok "No offending pattern found: $($patch.Description)"
			continue
		}

		$updated = [regex]::Replace($content, $patch.Pattern, $patch.Replacement)
		Set-Content -Path $patch.Path -Value $updated -NoNewline -Encoding UTF8

		$verifyContent = Get-Content -Path $patch.Path -Raw
		$remainingMatches = [regex]::Matches($verifyContent, $patch.Pattern)

		if ($remainingMatches.Count -gt 0) {
			throw "CA1859 patch verification failed for $($patch.Path). Remaining matches: $($remainingMatches.Count)"
		}

		Write-Ok "Patched $($matches.Count) occurrence(s): $($patch.Description)"
	}

	Test-Ca1859PatchVerification
}

# ── Build Pipeline ───────────────────────────────────────────────────────────

function Invoke-RdpAuditBuildPipeline {
	Write-Section 'Validation'

	if (-not (Test-Path -Path $script:SolutionPath)) {
		throw "Solution file not found: $($script:SolutionPath)"
	}

	if (-not (Test-Path -Path $script:PublishScriptPath)) {
		throw "Publish script not found: $($script:PublishScriptPath)"
	}

	Write-Section 'dotnet restore'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('restore', '.\RdpAudit.sln') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet restore failed.'

	Write-Section 'dotnet build'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('build', '.\RdpAudit.sln', '-c', 'Release', '--no-restore') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet build failed.'

	Write-Section 'dotnet test'
	Invoke-CheckedCommand `
		-FilePath 'dotnet' `
		-Arguments @('test', '.\RdpAudit.sln', '-c', 'Release', '--no-build') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'dotnet test failed.'

	Write-Section 'publish.ps1'
	Invoke-CheckedCommand `
		-FilePath 'pwsh' `
		-Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', '.\publish.ps1') `
		-WorkingDirectory $script:RepositoryDirectory `
		-FailureMessage 'publish.ps1 failed.'
}

function Start-Configurator {
	if ($SkipLaunch) {
		Write-Info 'Configurator launch skipped by parameter.'
		return
	}

	Write-Section 'Launch Configurator'

	if (-not (Test-Path -Path $script:ConfiguratorPath)) {
		Write-WarningMessage "Configurator executable not found: $($script:ConfiguratorPath)"
		return
	}

	Write-Ok "Launching: $($script:ConfiguratorPath)"
	Start-Process -FilePath $script:ConfiguratorPath -WorkingDirectory (Split-Path -Path $script:ConfiguratorPath -Parent)
}

# ── Main Flow ────────────────────────────────────────────────────────────────

function Invoke-Main {
	Write-Section 'RdpAudit Installer'

	Write-Info "Work directory     : $WorkDirectory"
	Write-Info "Repository         : $RepositoryUrl"
	Write-Info "Branch             : $RepositoryBranch"
	Write-Info "MessagePack target : $SafeMessagePackVersion"

	$prerequisites = @(Get-PrerequisiteStatus)
	Show-PrerequisiteStatus -Items $prerequisites

	if (-not (Test-MandatoryPrerequisites -Items $prerequisites)) {
		$installResult = Install-MissingPrerequisites -Items $prerequisites
		if (-not $installResult) {
			throw 'Prerequisites are not satisfied.'
		}

		Write-Section 'Re-check Prerequisites'
		$prerequisites = @(Get-PrerequisiteStatus)
		Show-PrerequisiteStatus -Items $prerequisites

		if (-not (Test-MandatoryPrerequisites -Items $prerequisites)) {
			throw 'Some mandatory prerequisites are still missing after installation.'
		}
	}

	Write-Ok 'All mandatory prerequisites are satisfied.'

	$proceed = Confirm-Action -Prompt 'Proceed with full RdpAudit installation?' -DefaultYes $true
	if (-not $proceed) {
		Write-Info 'Installation cancelled by user.'
		return
	}

	Initialize-Workspace
	Sync-Repository
	Set-DotNetSdkGlobalJson
	Update-MessagePackPackageReference
	Update-Ca1859SourceWarnings
	Invoke-RdpAuditBuildPipeline
	Start-Configurator

	Write-Section 'Completed'
	Write-Ok 'RdpAudit installation pipeline completed successfully.'
}

try {
	Invoke-Main
	exit 0
} catch {
	Write-Section 'Fatal Error'
	Write-ErrorMessage $_.Exception.Message

	if ($null -ne $_.ScriptStackTrace) {
		Write-Host ''
		Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
	}

	exit 1
}
