# LUCI config

This directory contains LUCI configuration.

## Directory structure

- [`main.star`](./main.star): The high-level LUCI configuration given as a
  [Starlark](https://github.com/google/starlark-go) script. By processing this file with
  [lucicfg](https://chromium.googlesource.com/infra/luci/luci-go/+/HEAD/lucicfg/README.md),
  low-level \*.cfg will be generated under `./generated/`.
- [`generated/`](./generated/): The directory containing \*.cfg generated from `main.star`.
- [`recipes.cfg`](./recipes.cfg): The file defining the dependencies for our recipes such as
  [modules](https://chromium.googlesource.com/chromium/tools/depot_tools.git/+/HEAD/recipes/README.recipes.md#Recipe-Modules).
  Whenever those dependencies are updated the
  [Recipe Roller bot](https://chromium-review.googlesource.com/q/project:crosvm/crosvm+owner:recipe-mega-autoroller%2540chops-service-accounts.iam.gserviceaccount.com)
  will update this file with the latest revision hashes.

## Making changes

1. Modify the `main.star`
1. Run `./main.star`. Then, cfg file(s) in `generated/` are updated.
1. Run `lucicfg validate main.star`. This will send the config to LUCI to verify the generated
   config is valid.
