//! Generate Kotlin or Swift bindings from the built `kovanica_light_ffi` library.
//!
//! `cargo run -p kovanica-light-ffi --features bindgen --bin kovanica-light-bindgen -- generate --library target/debug/libkovanica_light_ffi.so --language kotlin --out-dir apps/android/app/src/main/java`

fn main() {
    uniffi::uniffi_bindgen_main();
}
