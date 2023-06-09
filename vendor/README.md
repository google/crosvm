# Vendor directory

`/vendor/` directory facilitates maintaining downstream custom code. generic crates, containing
either default implementation or stubs, live in `/vendor/generic/` directory. The upstream code
imports these generic crates from various Cargo.toml files.

Downstream product specific crates will live under `/vendor/<product_name>/` directory. Downstream
will replace `/vendor/generic/`crate imports with downstream crate path.
