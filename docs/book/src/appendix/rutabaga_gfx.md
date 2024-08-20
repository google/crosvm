# Rutabaga Virtual Graphics Interface

The Rutabaga Virtual Graphics Interface (VGI) is a cross-platform abstraction for GPU and display
virtualization. The virtio-gpu
[context type](https://www.phoronix.com/news/VirtIO-Linux-5.16-Ctx-Type) feature is used to dispatch
commands between various Rust, C++, and C implementations. The diagram below does not exhaustively
depict all available context types.

<!-- Image from https://goto.google.com/crosvm-rutabaga-diagram -->

![rutabaga diagram](images/rutabaga_gfx.png)

## Rust API

Although hosted in the crosvm repository, the Rutabaga VGI is designed to be portable across VMM
implementations. The Rust API is available on [crates.io](https://crates.io/crates/rutabaga_gfx).

## Rutabaga C API

The following documentation shows how to build Rutabaga's C API with gfxstream enabled, which is the
common use case.

### Build dependencies

```sh
sudo apt install libdrm libglm-dev libstb-dev
```

### Install libaemu

```sh
git clone https://android.googlesource.com/platform/hardware/google/aemu
cd aemu/
git checkout v0.1.2-aemu-release
cmake -DAEMU_COMMON_GEN_PKGCONFIG=ON \
       -DAEMU_COMMON_BUILD_CONFIG=gfxstream \
       -DENABLE_VKCEREAL_TESTS=OFF -B build
cmake --build build -j
sudo cmake --install build
```

### Install gfxstream host

```sh
git clone https://android.googlesource.com/platform/hardware/google/gfxstream
cd gfxstream/
meson setup host-build/
meson install -C host-build/
```

### Install FFI bindings to Rutabaga

```sh
cd $(crosvm_dir)/rutabaga_gfx/ffi/
meson setup rutabaga-ffi-build/
meson install -C rutabaga-ffi-build/
```

### Latest releases for potential packaging

- [Rutabaga FFI v0.1.2](https://crates.io/crates/rutabaga_gfx_ffi)
- [gfxstream v0.1.2](https://android.googlesource.com/platform/hardware/google/gfxstream/+/refs/tags/v0.1.2-gfxstream-release)
- [AEMU v0.1.2](https://android.googlesource.com/platform/hardware/google/aemu/+/refs/tags/v0.1.2-aemu-release)

# Kumquat Media Server

The Kumquat Media server provides a way to test virtio multi-media protocols without a virtual
machine. The following example shows how to run GL and Vulkan apps with `virtio-gpu` +
`gfxstream-vulkan`. Full windowing will only work on platforms that support `dma_buf` and
`dma_fence`.

Only headless apps are likely to work on Nvidia, and requires
[this change](https://crrev.com/c/5698371).

## Build GPU-enabled server

First install [libaemu](#install-libaemu) and the [gfxstream-host](#install-gfxstream-host), then:

```sh
cd $(crosvm_dir)/rutabaga_gfx/kumquat/server/
cargo build --features=gfxstream
```

## Build and install client library

```sh
cd $(crosvm_dir)/rutabaga_gfx/kumquat/gpu_client/
meson setup client-build
ninja -C client-build/ install
```

## Build gfxstream guest

The same repo as gfxstream host is used, but with a different build configuration.

```sh
cd $(gfxstream_dir)
meson setup guest-build/ -Dgfxstream-build=guest
ninja -C guest-build/
```

## Run apps

In one terminal:

```sh
cd $(crosvm_dir)/rutabaga_gfx/kumquat/server/
./target/debug/kumquat
```

In another terminal, run:

```sh
export MESA_LOADER_DRIVER_OVERRIDE=zink
export VIRTGPU_KUMQUAT=1
export VK_ICD_FILENAMES=$(gfxstream_dir)/guest-build/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
vkcube
```

# Linux guests

To test gfxstream with Debian guests, make sure your display environment is headless.

```
systemctl set-default multi-user.target
```

Build gfxstream-vk:

```sh
cd $(gfxstream_dir)
meson setup guest-build/ -Dgfxstream-build=guest
ninja -C guest-build/
```

Start the compositor:

```sh
export MESA_LOADER_DRIVER_OVERRIDE=zink
export VK_ICD_FILENAMES=$(gfxstream_dir)/guest-build/guest/vulkan/gfxstream_vk_devenv_icd.x86_64.json
weston --backend=drm
```

# Contributing to gfxstream

To contribute to gfxstream without an Android tree:

```sh
git clone https://android.googlesource.com/platform/hardware/google/gfxstream
git commit -a -m blah
git push origin HEAD:refs/for/main
```

The AOSP Gerrit instance will ask for an identity. Follow the instructions, a Google account is
needed.
