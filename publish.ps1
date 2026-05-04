param(
	[string]$Version = "1.0.0",
	[string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$out = Join-Path $PSScriptRoot "publish"

function Publish-Project {
	param(
		[Parameter(Mandatory=$true)][string]$Project,
		[Parameter(Mandatory=$true)][string]$Subdir
	)

	$target = Join-Path $out $Subdir
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

if (Test-Path $out) {
	Remove-Item -Recurse -Force $out
}

Publish-Project -Project "src/RdpAudit.Service/RdpAudit.Service.csproj"           -Subdir "Service"
Publish-Project -Project "src/RdpAudit.Configurator/RdpAudit.Configurator.csproj" -Subdir "Configurator"

Write-Host "Done -> $out" -ForegroundColor Green
