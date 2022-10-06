# This script helps in building and uploading libslirp dll to google storage.
# The prebuilts are downloaded primarily by test bots and developers.
# Only googlers can upload the library to the cloud storage.

param(
  [switch] $skip_msys_setup,
  [int] $version = $(throw "specify version to upload")
)

$BASE_PATH = $env:TEMP
$MSYS_INSTALLER = $BASE_PATH + '\msys2.exe'
$MSYS_PATH = $BASE_PATH + '\msys64'
$LIBSLIRP_PATH = $BASE_PATH + '\libslirp'
$LIBSLIRP_REPO_URL = 'https://gitlab.freedesktop.org/slirp/libslirp.git'
$GS_BASE_URL = 'gs://chromeos-localmirror/distfiles/prebuilts/windows/x86_64/gnu/libslirp/'


# The upstream libslirp library is compiled as dll with a lot of dependencies.
# We compile the library as static binary by applying following patch.
$LIBSLIRP_STATIC_COMPILE = @"
diff --git a/meson.build b/meson.build
index 7e7d818..9be3c20 100644
--- a/meson.build
+++ b/meson.build
@@ -59,7 +59,8 @@ lt_version = '@0@.@1@.@2@'.format(lt_current - lt_age, lt_age, lt_revision)

 host_system = host_machine.system()

-glib_dep = dependency('glib-2.0')
+glib_dep = dependency('glib-2.0', static: true)
+iconv_dep = dependency('iconv', static: true)

 add_project_arguments(cc.get_supported_arguments('-Wmissing-prototypes', '-Wstrict-prototypes',
                                                  '-Wredundant-decls', '-Wundef', '-Wwrite-strings'),
@@ -127,6 +128,7 @@ sources = [

 mapfile = 'src/libslirp.map'
 vflag = []
+vflag += '-Wl,-Bstatic'
 vflag_test = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), mapfile)
 if cc.has_link_argument(vflag_test)
   vflag += vflag_test
@@ -147,7 +149,7 @@ lib = library('slirp', sources,
   c_args : cargs,
   link_args : vflag,
   link_depends : mapfile,
-  dependencies : [glib_dep, platform_deps],
+  dependencies : [glib_dep, platform_deps, iconv_dep],
   install : install_devel or get_option('default_library') == 'shared',
 )


"@


Set-PSDebug -Trace 2

try {
  if (-not $skip_msys_setup) {
    # Download the archive
    Start-BitsTransfer -Source 'https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-base-x86_64-latest.sfx.exe' -Destination $MSYS_INSTALLER
    $MSYS_DEST_ARG = '-o' + $BASE_PATH
    & $MSYS_INSTALLER -y $MSYS_DEST_ARG # Extract to C:\msys64

    $Env:PATH += $Env:PATH + ";" + $MSYS_PATH + "\usr\bin;" + $MSYS_PATH + "\mingw64\usr\bin;" + $MSYS_PATH + "\mingw64\bin"

    # Use bash from the installed msys.
    $bash_cmd = $MSYS_PATH + "\usr\bin\bash.exe"
    # Run for the first time
    & $bash_cmd -lc ' '
    # Update MSYS2
    & $bash_cmd -lc 'pacman --noconfirm -Syuu'  # Core update (in case any core packages are outdated)
    & $bash_cmd -lc 'pacman --noconfirm -Syuu'  # Normal update

    #Install dependencies
    & $bash_cmd -lc 'pacman --noconfirm -Syuu mingw-w64-x86_64-meson ninja git mingw-w64-x86_64-gcc mingw-w64-x86_64-glib2 mingw-w64-x86_64-pkg-config'
  }

  # Clone repo
  git clone $LIBSLIRP_REPO_URL $LIBSLIRP_PATH

  Push-Location
  Set-Location $LIBSLIRP_PATH

  Write-Output $LIBSLIRP_STATIC_COMPILE | git apply -


  meson release --buildtype release
  ninja -C release
  meson debug --buildtype debug
  ninja -C debug

  Copy-Item .\release\libslirp.dll.a .\release\libslirp.lib
  Copy-Item .\debug\libslirp.dll.a .\debug\libslirp.lib

  Write-Host Release binaries are located at: $LIBSLIRP_PATH\release\libslirp-0.dll and $LIBSLIRP_PATH\release\libslirp.lib
  Write-Host Debug binaries are located at: $LIBSLIRP_PATH\debug\libslirp-0.dll and $LIBSLIRP_PATH\debug\libslirp.lib

  Write-Host Uploading build binaries
  foreach ($build_type in 'release', 'debug') {
    foreach ($prebuilt in 'libslirp-0.dll', 'libslirp.lib') {
      gsutil cp -n -a public-read $LIBSLIRP_PATH\$build_type\$prebuilt $GS_BASE_URL/$build_type/$version/$prebuilt
    }
  }
}


finally {
  Set-PSDebug -Trace 0
  Write-Host Cleaning up
  Remove-Item $MSYS_INSTALLER # Delete the archive again
  Pop-Location
}
