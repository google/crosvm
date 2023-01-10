# Building Crosvm on Windows

This page describes how to build and develop crosvm on windows. If you are targeting linux, please
see [Building Crosvm on linux](../building_crosvm.md)

NOTE: Following instruction assume that

- [git](https://git-scm.com/download/win) is installed and `git` command exists in your `Env:PATH`
- the commands are run in powershell

## Create base directory - `C:\src`

```ps1
mkdir C:\src
cd C:\src
```

## Checking out

Obtain the source code via git clone.

```ps1
git clone https://chromium.googlesource.com/crosvm/crosvm
```

## Setting up the development environment

Crosvm uses submodules to manage external dependencies. Initialize them via:

```ps1
cd crosvm
git submodule update --init
```

It is recommended to enable automatic recursive operations to keep the submodules in sync with the
main repository (But do not push them, as that can conflict with `repo`):

```ps1
git config submodule.recurse true
git config push.recurseSubmodules no
```

`install-deps.ps1` install the necessary tools needed to build crosvm on windows. In addition to
installing the scripts, the script also sets up environment variables.

The below script may prompt you to install msvc toolchain via Visual Studio community edition.

```ps1
./tools/install-deps.ps1
```

NOTE: Above step sets up enviroment variables. You may need to either start a new powershell session
or reload the environemnt variables,

## Build crosvm

```ps1
cargo build --features all-msvc64,whpx
```
