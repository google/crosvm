:: Copyright 2022 The Chromium OS Authors. All rights reserved.
:: Use of this source code is governed by a BSD-style license that can be
:: found in the LICENSE file.

:: Make environment changes (cd, env vars, etc.) local, so they don't affect the calling batch file
setlocal

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration
cd %KOKORO_ARTIFACTS_DIR%\git\crosvm

:: Pin rustup to a known/tested version.
set rustup_version=1.24.3

:: Install rust toolchain through rustup.
echo [%TIME%] installing rustup %rustup_version%
choco install -y rustup.install --version=%rustup_version%

:: Reload path for installed rustup binary
call RefreshEnv.cmd

:: Toolchain version and necessary components will be automatically picked
:: up from rust-toolchain
cargo install bindgen

:: Reload path for installed rust toolchain.
call RefreshEnv.cmd

:: Log the version of the Rust toolchain
echo [%TIME%] Using Rust toolchain version:
cargo --version
rustc --version

echo [%TIME%] Calling crosvm\build_test.py
py ./tools/windows/build_test.py --copy True --job_type kokoro --skip_file_name .windows_build_test_skip
if %ERRORLEVEL% neq 0 ( exit /b %ERRORLEVEL% )

exit /b %ERRORLEVEL%
