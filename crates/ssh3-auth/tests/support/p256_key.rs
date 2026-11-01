// Shared test-only key generation. Keys are generated from OS entropy for each
// call; no private-key fixtures are stored in the repository. Encoding the key
// lets ssh-key parse it without enabling its older P-256 arithmetic backend.
fn test_p256_private_key() -> ssh_key::PrivateKey {
    use rsa::rand_core::RngCore as _;

    fn ssh_string(output: &mut Vec<u8>, bytes: &[u8]) {
        output.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        output.extend_from_slice(bytes);
    }

    let (key, secret) = loop {
        let mut secret = [0u8; 32];
        rsa::rand_core::OsRng.fill_bytes(&mut secret);
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&secret) {
            break (key, secret);
        }
    };
    let point = key.verifying_key().to_sec1_point(false);
    let mut public = Vec::new();
    ssh_string(&mut public, b"ecdsa-sha2-nistp256");
    ssh_string(&mut public, b"nistp256");
    ssh_string(&mut public, point.as_bytes());

    let mut private = Vec::new();
    let checkint = rsa::rand_core::OsRng.next_u32().to_be_bytes();
    private.extend_from_slice(&checkint);
    private.extend_from_slice(&checkint);
    private.extend_from_slice(&public);
    let mut scalar = Vec::with_capacity(33);
    if secret[0] & 0x80 != 0 {
        scalar.push(0);
    }
    scalar.extend_from_slice(&secret);
    ssh_string(&mut private, &scalar);
    ssh_string(&mut private, b"ephemeral SSH3 test identity");
    let padding = (8 - private.len() % 8) % 8;
    private.extend(1..=padding as u8);

    let mut encoded = b"openssh-key-v1\0".to_vec();
    ssh_string(&mut encoded, b"none");
    ssh_string(&mut encoded, b"none");
    ssh_string(&mut encoded, b"");
    encoded.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut encoded, &public);
    ssh_string(&mut encoded, &private);
    ssh_key::PrivateKey::from_bytes(&encoded).expect("generated P-256 SSH key should decode")
}
