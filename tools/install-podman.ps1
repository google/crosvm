<#
.Description
The script installs and sets up podman.
.PARAMETER BASE_DIR
Determines where the binaries will be downloaded. This defaults to user's temp directory.
#>
param (
	[Parameter(
		Position = 0
	)]
	[string]$BASE_DIR = $Env:TEMP  ##
)

$BASE_DIR = $BASE_DIR + "\"
$PODMAN_VERSION = '4.7.2'
$PODMAN_SHA256 = "2124ac24e2c730f16e07e8eb033d5675d0f6123669c27d525d43d2f51f96b1ba"
$PODMAN_URL = "https://github.com/containers/podman/releases/download/v$PODMAN_VERSION/podman-$PODMAN_VERSION-setup.exe"
$PODMAN_SETUP = $BASE_DIR + 'podman-setup.exe'
$PODMAN_INSTALL_PATH = "C:\Program Files\RedHat\Podman\"

# Download podman
Invoke-WebRequest $PODMAN_URL -Out $PODMAN_SETUP
Write-Host "Verifying podman integrity"
if ((Get-FileHash $PODMAN_SETUP -Algorithm SHA256).Hash -ne $PODMAN_SHA256) {
	Write-Host "$PODMAN_SETUP sha did not match"
	Break
}

# Install podman
Write-Host "Installing podman. You may skip rebooting for machine for now"
Start-Process $PODMAN_SETUP /norestart -NoNewWindow -Wait

# Update PATH to contain podman directory.
$Env:PATH = $Env:PATH + ";" + $PODMAN_INSTALL_PATH

# create and start a wsl2 machine for podman to use
podman machine init
podman machine start


Write-Host "podman installed successfully. You may need to add $PODMAN_INSTALL_PATH to your PATH"
