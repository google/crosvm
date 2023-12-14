<#
.Description
Runs an ubuntu image. The image itself needs to be built on linux as per instructions at
https://crosvm.dev/book/running_crosvm/example_usage.html#preparing-the-guest-os-image

The console is a pipe at \\.\pipe\crosvm-debug that you can connect to using apps like
putty.
.PARAMETER IMAGE_DIR
Directory where initrd, rootfs and vmlinuz are located. Defaults to user's tmp directory.
.PARAMETER LOGS_DIR
Directory where logs will be written to. Defaults to user's tmp directory.
#>
param (
    [Parameter(
        Position = 0
    )]
    [string]$IMAGE_DIR = $Env:TEMP, ##
    [Parameter(
        Position = 1
    )]
    [string]$LOGS_DIR = $Env:TEMP  ##
)

$VMLINUZ = Join-Path $IMAGE_DIR "vmlinuz"
$ROOTFS = Join-Path $IMAGE_DIR "rootfs"
$INITRD = Join-Path $IMAGE_DIR "initrd"
$SERIAL = "\\.\pipe\crosvm-debug"
$LOGS_DIR = Join-Path $LOGS_DIR "\"

$PATHS = $IMAGE_DIR, $VMLINUZ, $ROOTFS, $INITRD, $LOGS_DIR

foreach ($path in $PATHS) {
    if (!(Test-Path $path)) {
        throw (New-Object System.IO.FileNotFoundException("Path not found: $path", $path))
    }
}

cargo run --features "all-msvc64,whpx" -- `
    --log-level INFO `
    run-mp `
    --logs-directory $LOGS_DIR `
    --cpus 1 `
    --mem 4096 `
    --serial "hardware=serial,type=namedpipe,path=$SERIAL,num=1,console=true" `
    --params "nopat clocksource=jiffies root=/dev/vda5 loglevel=7 console=/dev/ttyS1 console=/dev/ttyS0"  `
    --host-guid "dontcare" `
    --rwdisk $ROOTFS `
    --initrd $INITRD `
    $VMLINUZ
