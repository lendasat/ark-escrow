fn main() {
    // On macOS, Ruby native extensions are loaded into the Ruby process at runtime,
    // so rb_* symbols are resolved dynamically. Tell the linker to allow undefined
    // symbols instead of failing at link time.
    if std::env::consts::OS == "macos" {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}
