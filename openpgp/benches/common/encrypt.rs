use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{
    padding::Padder, Armorer, Encryptor, LiteralWriter, Message, Signer,
};

use std::io::Write;

// naively encrypt, without caring for revocation or expiration
pub fn encrypt_to_cert(
    bytes: &[u8],
    cert: &Cert,
) -> sequoia_openpgp::Result<Vec<u8>> {
    let mut sink = vec![];
    let p = &StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(p, None)
        .supported()
        .for_transport_encryption()
        .for_storage_encryption();
    let message =
        Encryptor::for_recipients(Message::new(&mut sink), recipients)
            .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(sink)
}

// naively encrypt and sign, without caring for revocation or expiration
pub fn encrypt_to_cert_and_sign(
    bytes: &[u8],
    sender: &Cert,
    recipient: &Cert,
) -> sequoia_openpgp::Result<Vec<u8>> {
    let mut sink = vec![];

    let p = &StandardPolicy::new();
    let signing_keypair = sender
        .keys()
        .with_policy(p, None)
        .secret()
        .for_signing()
        .nth(0)
        .unwrap()
        .key()
        .clone()
        .into_keypair()?;

    let recipients = recipient
        .keys()
        .with_policy(p, None)
        .supported()
        .for_transport_encryption()
        .for_storage_encryption();

    let message = Message::new(&mut sink);
    let message = Armorer::new(message).build()?;
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let message = Padder::new(message).build()?;
    let message = Signer::new(message, signing_keypair)
        //.add_intended_recipient(&recipient)
        .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(sink)
}

pub fn encrypt_with_password(
    bytes: &[u8],
    password: &str,
) -> sequoia_openpgp::Result<Vec<u8>> {
    let mut sink = vec![];
    let message =
        Encryptor::with_passwords(Message::new(&mut sink), Some(password))
            .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(sink)
}
