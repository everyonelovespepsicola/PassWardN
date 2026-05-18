fn main() {
    // Only compile the resource on Windows
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("src/icon.ico");
        res.compile().unwrap();
    }
}
