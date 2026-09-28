fn main() {
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/kononexus-tester.ico");
        resource.set("ProductName", "KonoNexus Network Tester");
        resource.set("FileDescription", "KonoNexus WAN / Internet Network Tester");
        resource.set("LegalCopyright", "KonoNexus contributors");
        resource
            .compile()
            .expect("failed to embed Windows resources");
    }
}
