#[allow(unused_imports)]
#[allow(clippy::all)]
pub mod client {
  pub mod org_chromium_spaced;
  pub use org_chromium_spaced::*;
  pub mod org_chromium_vtpm;
  pub use org_chromium_vtpm::*;
  pub mod org_chromium_power_manager;
  pub use org_chromium_power_manager::*;
}
