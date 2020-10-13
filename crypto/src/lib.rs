pub mod cast128;
pub mod cast128_sboxes;

#[test]
fn cipher_generate_key_success() -> anyhow::Result<()> {
    cast128_generate_key();

    Ok(())
}

#[no_mangle]
pub extern "C" fn cast128_generate_key() {
    let mut cast128 = cast128::Cast128::default();
    if let Err(e) = cast128.generate_key(b"C238xs65pjy7HU9Q") {
        eprintln!("generate_key failed; error = {:#?}", e);
    } else {
        println!("generate_key success; cipher = {:#?}", cast128);
    }
}
