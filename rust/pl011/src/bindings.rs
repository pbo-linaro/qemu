#[cfg(MESON_BINDINGS_RS)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(MESON_BINDINGS_RS))]
include!("bindings.rs.inc");
