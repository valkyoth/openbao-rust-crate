fn main() -> openbao::Result<()> {
    // The direct reqwest dependency unifies native-tls onto the same reqwest
    // package. OpenBao must still select Rustls because only its rustls-tls
    // feature is enabled.
    let _client = openbao::Client::new("https://bao.example.com")?;
    Ok(())
}
