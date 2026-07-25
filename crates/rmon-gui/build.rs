fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/rmon.ico")
            .compile()
            .expect("embed rmon.ico as exe resource");
    }
}
