<#
.Description
The script installs binaries needed to build and run crosvm, including rust toolchain and protoc,
in User's temp directory and sets up system environment variables.
.PARAMETER BASE_DIR
Determines where the binaries will be installed. This defaults to user's temp directory.
#>
param (
    [Parameter(
        Position = 0
    )]
    [string]$BASE_DIR = $Env:TEMP  ## 
)

$BASE_DIR = $BASE_DIR + "\"
$PROTOC_VERSION = '21.12'
$PROTOC_SHA256 = "71852A30CF62975358EDFCBBFF93086E8857A079C8E4D6904881AA968D65C7F9"
$PROTOC_URL = "https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/protoc-$PROTOC_VERSION-win64.zip"
$PROTOC_ZIP = $BASE_DIR + 'protoc.zip'
$PROTOC_DIR = $BASE_DIR + 'protoc\'


$RUSTUP_INIT_VERSION = '1.25.1'
$RUSTUP_INIT_SHA256 = "2220DDB49FEA0E0945B1B5913E33D66BD223A67F19FD1C116BE0318DE7ED9D9C"
$RUSTUP_INIT_URL = "https://static.rust-lang.org/rustup/archive/$RUSTUP_INIT_VERSION/x86_64-pc-windows-msvc/rustup-init.exe"
$RUSTUP_INIT = $BASE_DIR + 'rustup-init.exe'

$CARGO_BINSTALL_VERSION = 'v0.19.3'
$CARGO_BINSTALL_URL = "https://github.com/cargo-bins/cargo-binstall/releases/download/$CARGO_BINSTALL_VERSION/cargo-binstall-x86_64-pc-windows-msvc.zip"

Write-Host "Installing in $BASE_DIR"

if (!(Test-Path $BASE_DIR -PathType Container)) {
    New-Item -ItemType Directory -Force -Path $BASE_DIR
}

Set-Location $BASE_DIR

# Install protobuf compiler
Invoke-WebRequest $PROTOC_URL -Out $PROTOC_ZIP
Write-Host "Verifying protoc integrity"
if ((Get-FileHash $PROTOC_ZIP -Algorithm SHA256).Hash -ne $PROTOC_SHA256)
{
    Write-Host "$PROTOC_ZIP sha did not match"
    Break
}
Expand-Archive -Path $PROTOC_ZIP -DestinationPath $PROTOC_DIR
$Env:PATH = $Env:PATH  + ";" + $PROTOC_DIR + "bin\"

# Update PATH to contain protobuf and depot_tools directory
[Environment]::SetEnvironmentVariable("Path", $Env:PATH, [System.EnvironmentVariableTarget]::User)

# Download rustup-init that helps setting up rustup and rust toolchain.
# Install protobuf compiler
Invoke-WebRequest $RUSTUP_INIT_URL -Out $RUSTUP_INIT
Write-Host "Verifying rustup_init integrity"
if ((Get-FileHash $RUSTUP_INIT -Algorithm SHA256).Hash -ne $RUSTUP_INIT_SHA256)
{
    Write-Host "$RUSTUP_INIT sha did not match"
    Break
}

# Install rustup and rust toolchain
& $RUSTUP_INIT

# Update PATH to to contain cargo home directory.
[Environment]::SetEnvironmentVariable("Path", $Env:PATH, [System.EnvironmentVariableTarget]::User)

# Cargo extension to install binary packages from github
$BINSTALL_ZIP = New-TemporaryFile
Invoke-WebRequest $CARGO_BINSTALL_URL -Out $BINSTALL_ZIP
$BINSTALL_DEST=((Get-Command cargo) | Get-Item).DirectoryName
Expand-Archive -Path $BINSTALL_ZIP -DestinationPath $BINSTALL_DEST

# Nextest is an improved test runner for cargo
cargo binstall --no-confirm cargo-nextest --version "0.9.49"

