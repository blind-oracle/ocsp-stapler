use std::{env, error::Error, fs, path::PathBuf};

const CRATE_NAME: &str = "ocsp-stapler";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=README_DOCS.md");

    fs::write(
        PathBuf::from(env::var("OUT_DIR")?).join("README-rustdocified.md"),
        readme_rustdocifier::rustdocify(
            &fs::read_to_string("README_DOCS.md")?,
            &env::var("CARGO_PKG_NAME")?,
            Some(&env::var("CARGO_PKG_VERSION")?),
            Some(CRATE_NAME),
        )?,
    )?;

    Ok(())
}
