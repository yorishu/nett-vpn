use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=nett.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numeric_version = format!("{},0", version.replace('.', ","));
    let source = out.join("nett.rc");
    let resource = out.join("nett-resource.o");
    fs::write(
        &source,
        format!(
            r#"1 ICON "nett.ico"
1 VERSIONINFO
FILEVERSION {numeric_version}
PRODUCTVERSION {numeric_version}
FILEOS 0x40004
FILETYPE 1
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "FileDescription", "nett is here\0"
            VALUE "FileVersion", "{version}\0"
            VALUE "ProductName", "nett\0"
            VALUE "ProductVersion", "{version}\0"
            VALUE "OriginalFilename", "nett.exe\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"#
        ),
    )
    .expect("write Windows resources");
    let status = Command::new("windres")
        .arg("-I")
        .arg(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .arg("-i")
        .arg(&source)
        .args(["-O", "coff", "-o"])
        .arg(&resource)
        .status()
        .expect("run windres from the Windows GNU toolchain");
    assert!(status.success(), "Windows resource compilation failed");
    println!("cargo:rustc-link-arg-bin=nett-vpn={}", resource.display());
}
