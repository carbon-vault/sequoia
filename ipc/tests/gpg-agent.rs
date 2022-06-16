//! Tests gpg-agent interaction.

use std::io::{self, Write};

use anyhow::Context as _;
use futures::StreamExt;

use sequoia_openpgp as openpgp;
use crate::openpgp::types::{
    HashAlgorithm,
    SymmetricAlgorithm,
};
use crate::openpgp::crypto::SessionKey;
use crate::openpgp::parse::{Parse, stream::*};
use crate::openpgp::serialize::{Serialize, stream::*};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::Policy;

use sequoia_ipc as ipc;
use crate::ipc::gnupg::{Context, Agent, KeyPair};

macro_rules! make_context {
    () => {{
        let ctx = match Context::ephemeral() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is GnuPG installed?", e);
                panic!("{}", e);
            },
        };
        match ctx.start("gpg-agent") {
            Ok(_) => (),
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is the GnuPG agent installed?", e);
                panic!("{}", e);
            },
        }
        ctx
    }};
}

#[tokio::test]
async fn nop() -> openpgp::Result<()> {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).await.unwrap();
    agent.send("NOP").unwrap();
    let response = agent.collect::<Vec<_>>().await;
    assert_eq!(response.len(), 1);
    assert!(response[0].is_ok());
    Ok(())
}

#[tokio::test]
async fn help() -> openpgp::Result<()>  {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).await.unwrap();
    agent.send("HELP").unwrap();
    let response = agent.collect::<Vec<_>>().await;
    assert!(response.len() > 3);
    assert!(response.iter().last().unwrap().is_ok());
    Ok(())
}

const MESSAGE: &str = "дружба";

fn gpg_import(ctx: &Context, what: &[u8]) -> openpgp::Result<()> {
    use std::process::{Command, Stdio};

    let mut gpg = Command::new("gpg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--homedir").arg(ctx.homedir().unwrap())
        .arg("--import")
        .spawn()
        .context("failed to start gpg")?;
    gpg.stdin.as_mut().unwrap().write_all(what)?;
    let output = gpg.wait_with_output()?;

    // We capture stdout and stderr, and use eprintln! so that the
    // output will be captured by Rust's test harness.  This way, the
    // output will be at the right position, instead of out-of-order
    // and garbled by the concurrent tests.
    if ! output.stdout.is_empty() {
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    }
    if ! output.stderr.is_empty() {
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    let status = output.status;
    if status.success() {
        Ok(())
    } else {
        use openpgp::armor;
        let mut w =
            armor::Writer::new(Vec::new(), armor::Kind::SecretKey)?;
        w.write_all(what)?;
        let buf = w.finalize()?;
        eprintln!("Failed to import the following key:\n\n\n{}\n\n",
                  String::from_utf8_lossy(&buf));
        Err(anyhow::anyhow!("gpg --import failed"))
    }
}

#[test]
fn sign() -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        dbg!(cs);
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_signing_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        let keypair = KeyPair::new(
            &ctx,
            cert.keys().with_policy(p, None).alive().revoked(false)
                .for_signing().take(1).next().unwrap().key())
            .unwrap();

        let mut message = Vec::new();
        {
            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to sign a literal data packet.
            let signer = Signer::new(message, keypair)
                 // XXX: Is this necessary?  If so, it shouldn't.
                .hash_algo(HashAlgorithm::SHA512).unwrap()
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                signer).build().unwrap();

            // Sign the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: &cert };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier = VerifierBuilder::from_bytes(&message)?
            .with_policy(p, None, helper)?;

        // Verify the data.
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);
    }

    struct Helper<'a> {
        cert: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                           -> openpgp::Result<Vec<openpgp::Cert>> {
            // Return public keys for signature verification here.
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure)
                 -> openpgp::Result<()> {
            // In this function, we implement our signature verification
            // policy.

            let mut good = false;
            for (i, layer) in structure.into_iter().enumerate() {
                match (i, layer) {
                    // First, we are interested in signatures over the
                    // data, i.e. level 0 signatures.
                    (0, MessageLayer::SignatureGroup { results }) => {
                        // Finally, given a VerificationResult, which only says
                        // whether the signature checks out mathematically, we apply
                        // our policy.
                        match results.into_iter().next() {
                            Some(Ok(_)) => good = true,
                            Some(Err(e)) =>
                                return Err(openpgp::Error::from(e).into()),
                            None => (),
                        }
                    },
                    _ => return Err(anyhow::anyhow!(
                        "Unexpected message structure")),
                }
            }

            if good {
                Ok(()) // Good signature.
            } else {
                Err(anyhow::anyhow!("Signature verification failed"))
            }
        }
    }
    Ok(())
}

const BAD_SIGN_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEYqsJ8xYJKwYBBAHaRw8BAQdAfUB/E4q/4KXVCYOwdx/KRJ5dfUzuWhKQS92F
uIaVMuEAAQCBqKT9nDUo6VcdJkU9euHtJnVyzK8r9RVZDpFpKFHr5Q94wsALBB8W
CgB9BYJiqwnzAwsJBwkQj3PPCo6za29HFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMu
c2VxdW9pYS1wZ3Aub3JnsWbhoMETNIFiPfRvM64Q1+g7Cpjf/w/QT5cVSrq1cW4D
FQoIApsBAh4BFiEEbr3AxOjW2vy6BFtuj3PPCo6za28AAFVOAP0ZVd7jchLC7P9d
+Cu2rUJ3sDWSmlZdDqFAYRIP87Ka2AEAlDYC/9ooEC+NhG00xpO8EvGxpq0S9frJ
aFkUqfBOaQ/NE3NvbWVvbmVAZXhhbXBsZS5vcmfCwA4EExYKAIAFgmKrCfMDCwkH
CRCPc88KjrNrb0cUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBncC5v
cmdOTl3Tzas+nFXSEQCscDTYrb02k5nGyUkxJB0OYhHVUwMVCggCmQECmwECHgEW
IQRuvcDE6Nba/LoEW26Pc88KjrNrbwAAOwQA/3JJh5DP5HBY2yi1pNWvw45oqDl5
GH6BJWieDbevaGagAQDcRo9xM8d44PRIxbl/RiKAtVll9LufuJ0aRRmdxQaqCsdY
BGKrCfMWCSsGAQQB2kcPAQEHQMRGCST173LcHXGM4rL4jc7GrT1ohOlp8bSAnt9r
bCAEAAEAxcO+aAGmeAj5oX5oI4XWP/PdkopaXzZpP+I8Efj2lgMQTMLAvwQYFgoB
MQWCYqsJ8wkQj3PPCo6za29HFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2VxdW9p
YS1wZ3Aub3Jno3ks/10/XSnOV+cQlINOFse1UbCdEosHuo4nDb5HOZoCmwK+oAQZ
FgoAbwWCYqsJ8wkQKcPDPpLCO3FHFAAAAAAAHgAgc2FsdEBub3RhdGlvbnMuc2Vx
dW9pYS1wZ3Aub3JnsMBBdQlPZkZCAi9BDWTSpnxVL5wQSxVdkMjLoJw9RVEWIQQS
PtMJ9bs65OYxKoYpw8M+ksI7cQAA3bQBAMHk5D+pg89YiB+AxNhYz1218zRViZUX
5fQjGcal6s1GAQCP0pmojI6vMXiWaOo1ATGxloqvoWj3V+qA5RtPbxmKBRYhBG69
wMTo1tr8ugRbbo9zzwqOs2tvAADgzgEA22TQn3B2cc5hKL/oIrCz1Dp1FkF4iGkI
y0KLnG75ZUMA/RcO6tgrtzHBGpXwHN2U9S+z4qtdqN6sPHBJ9rhVRLwD
=zzAE
-----END PGP PRIVATE KEY BLOCK-----
";

#[test]
fn bad_sign_key_0() -> openpgp::Result<()> {
    bad_sign_key()
}

#[test]
fn bad_sign_key_1() -> openpgp::Result<()> {
    bad_sign_key()
}

#[test]
fn bad_sign_key_2() -> openpgp::Result<()> {
    bad_sign_key()
}

#[test]
fn bad_sign_key_3() -> openpgp::Result<()> {
    bad_sign_key()
}

fn bad_sign_key() -> openpgp::Result<()> {
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    let cert = openpgp::Cert::from_bytes(BAD_SIGN_KEY)?;

    {
        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        let keypair = KeyPair::new(
            &ctx,
            cert.keys().with_policy(p, None).alive().revoked(false)
                .for_signing().take(1).next().unwrap().key())
            .unwrap();

        let mut message = Vec::new();
        {
            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to sign a literal data packet.
            let signer = Signer::new(message, keypair)
                 // XXX: Is this necessary?  If so, it shouldn't.
                .hash_algo(HashAlgorithm::SHA512).unwrap()
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                signer).build().unwrap();

            // Sign the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: &cert };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier = VerifierBuilder::from_bytes(&message)?
            .with_policy(p, None, helper)?;

        // Verify the data.
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);
    }

    struct Helper<'a> {
        cert: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                           -> openpgp::Result<Vec<openpgp::Cert>> {
            // Return public keys for signature verification here.
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure)
                 -> openpgp::Result<()> {
            // In this function, we implement our signature verification
            // policy.

            let mut good = false;
            for (i, layer) in structure.into_iter().enumerate() {
                match (i, layer) {
                    // First, we are interested in signatures over the
                    // data, i.e. level 0 signatures.
                    (0, MessageLayer::SignatureGroup { results }) => {
                        // Finally, given a VerificationResult, which only says
                        // whether the signature checks out mathematically, we apply
                        // our policy.
                        match results.into_iter().next() {
                            Some(Ok(_)) => good = true,
                            Some(Err(e)) =>
                                return Err(openpgp::Error::from(e).into()),
                            None => (),
                        }
                    },
                    _ => return Err(anyhow::anyhow!(
                        "Unexpected message structure")),
                }
            }

            if good {
                Ok(()) // Good signature.
            } else {
                Err(anyhow::anyhow!("Signature verification failed"))
            }
        }
    }
    Ok(())
}

#[test]
fn decrypt() -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
        dbg!(cs);
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_transport_encryption_subkey()
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        let mut message = Vec::new();
        {
            let recipients =
                cert.keys().with_policy(p, None).alive().revoked(false)
                .for_transport_encryption()
                .map(|ka| ka.key())
                .collect::<Vec<_>>();

            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to encrypt a literal data packet.
            let encryptor =
                Encryptor::for_recipients(message, recipients)
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                encryptor).build().unwrap();

            // Encrypt the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the recipient's secret key to the
        // decryptor.
        let helper = Helper { policy: p, ctx: &ctx, cert: &cert, };

        // Now, create a decryptor with a helper using the given Certs.
        let mut decryptor = DecryptorBuilder::from_bytes(&message).unwrap()
            .with_policy(p, None, helper).unwrap();

        // Decrypt the data.
        let mut sink = Vec::new();
        io::copy(&mut decryptor, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);

        struct Helper<'a> {
            policy: &'a dyn Policy,
            ctx: &'a Context,
            cert: &'a openpgp::Cert,
        }

        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                               -> openpgp::Result<Vec<openpgp::Cert>> {
                // Return public keys for signature verification here.
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure)
                     -> openpgp::Result<()> {
                // Implement your signature verification policy here.
                Ok(())
            }
        }

        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt<D>(&mut self,
                          pkesks: &[openpgp::packet::PKESK],
                          _skesks: &[openpgp::packet::SKESK],
                          sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D)
                          -> openpgp::Result<Option<openpgp::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {
                let mut keypair = KeyPair::new(
                    self.ctx,
                    self.cert.keys().with_policy(self.policy, None)
                        .for_storage_encryption().for_transport_encryption()
                        .take(1).next().unwrap().key())
                    .unwrap();

                pkesks[0].decrypt(&mut keypair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));

                // XXX: In production code, return the Fingerprint of the
                // recipient's Cert here
                Ok(None)
            }
        }
    }
    Ok(())
}
