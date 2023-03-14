// 2>/dev/null ; echo '#[no_mangle] pub extern "C" fn free(_: usize) {}' | rustc --crate-name nofree --crate-type cdylib -o nofree.so - && cargo build -p sequoia-openpgp --no-default-features --features=allow-experimental-crypto,allow-variable-time-crypto,crypto-$1 --example secret-leak-detector $2 && for t in clean_basecase leak_basecase test_memzero test_libc_memset test_protected test_protected_mpi test_session_key test_encrypted test_password test_ed25519 test_aes_256_encryption test_aes_256_decryption ; do RUST_BACKTRACE=1 LD_PRELOAD=nofree.so target/debug/examples/secret-leak-detector $t ; done ; exit $?
//
// Note: This is also a shell script.

use std::{
    io::{Read, Write},
};

use sequoia_openpgp::{
    crypto::{mem, mpi::{MPI, ProtectedMPI}, Password, SessionKey, Signer},
    fmt::hex,
    packet::{
        key::{Key4, PrimaryRole},
        PKESK,
        SKESK,
    },
    serialize::stream::{
        Message, Encryptor, LiteralWriter,
    },
    parse::{
        stream::*,
        Parse,
    },
    policy::StandardPolicy,
    types::{
        HashAlgorithm,
        SymmetricAlgorithm,
    },
    Cert,
    Fingerprint,
    KeyHandle,
    Result,

};

/// How often to repeat a test.
const N: usize = 1;

/// The secret to use and scan for.
const NEEDLE: &[u8] = b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@";
const N0: u8 = NEEDLE[0];

/// Makes the current program SEGFAULT.
#[allow(dead_code)]
fn segfault() -> u8 {
    unsafe {
        let p: *const u8 = std::mem::transmute(0u64);
        *p
    }
}

/// A clean base case that does nothing.
fn clean_basecase() {
}

fn careful_to_vec<B: AsRef<[u8]>>(b: B) -> Vec<u8> {
    let b = b.as_ref();
    let mut r = vec![0; b.len()];
    b.iter().zip(r.iter_mut()).for_each(|(f, t)| *t = *f);
    r
}

fn check_secret(v: &[u8]) {
    assert_eq!(v.iter().cloned().map(usize::from).sum::<usize>(),
               NEEDLE.len() * N0 as usize);
}

/// A leaky base case that allocates a Vector.
fn leak_basecase() {
    let v = NEEDLE.to_vec();
    check_secret(&v);
}

/// A test case that allocates a Vector and securely overwrites it
/// using [`memsec::memzero`].
fn test_memzero() {
    let mut v = careful_to_vec(NEEDLE);
    check_secret(&v);
    let len = v.len();
    unsafe {
        memsec::memzero(v.as_mut_ptr(), len);
    }
}

/// A test case that allocates a Vector and securely overwrites it
/// using [`libc::memset`].
fn test_libc_memset() {
    let mut v = careful_to_vec(NEEDLE);
    check_secret(&v);
    let len = v.len();
    unsafe {
        libc::memset(v.as_mut_ptr() as _, 0, len);
    }
}

/// A test case that allocates a mem::Protected and drops it.
fn test_protected() {
    let v: mem::Protected = NEEDLE.into();
    check_secret(&v);
    let v: mem::Protected = NEEDLE.to_vec().into();
    check_secret(&v);
}

/// A test case that allocates a mem::Protected and drops it.
fn test_protected_mpi() {
    let v: ProtectedMPI = NEEDLE.to_vec().into_boxed_slice().into();
    check_secret(v.value());
    let v: ProtectedMPI = NEEDLE.to_vec().into();
    check_secret(v.value());
    let v: ProtectedMPI = mem::Protected::from(NEEDLE).into();
    check_secret(v.value());
    let v: ProtectedMPI = MPI::new(NEEDLE).into();
    check_secret(v.value());
}

/// A test case that allocates a SessionKey and drops it.
fn test_session_key() {
    let v: SessionKey = NEEDLE.into();
    check_secret(&v);
    let v: SessionKey = NEEDLE.to_vec().into();
    check_secret(&v);
}

/// A test case that allocates a mem::Encrypted, uses it once, then
/// drops it.
fn test_encrypted() {
    let m = mem::Encrypted::new(NEEDLE.into());
    m.map(|v| check_secret(&v));
}

/// A test case that allocates a Password, uses it once, then drops
/// it.
fn test_password() {
    let p = Password::from(NEEDLE);
    p.map(|v| check_secret(&v));
}

/// A test case that allocates a Key4, uses it once, then
/// drops it.
fn test_ed25519() {
    let k = Key4::<_, PrimaryRole>::import_secret_ed25519(NEEDLE, None)
        .unwrap();
    let mut kp = k.into_keypair().unwrap();
    kp.sign(HashAlgorithm::SHA256, b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
}

/// A test case that encrypts a message using AES-256.
fn test_aes_256_encryption() -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::with_session_key(
        message, SymmetricAlgorithm::AES256, NEEDLE.into())?
        .add_passwords(Some(Password::from(NEEDLE)))
        .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(b"Hello world.")?;
    w.finalize()?;
    Ok(sink)
}

/// A test case that decrypts a message using AES-256.
fn test_aes_256_decryption(ciphertext: &[u8]) -> Result<()> {
    let p = &StandardPolicy::new();

    struct Helper {}
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
            Ok(Vec::new())
        }
        fn check(&mut self, _structure: MessageStructure) -> Result<()> {
            Ok(())
        }
    }
    impl DecryptionHelper for Helper {
        fn decrypt<D>(&mut self, _: &[PKESK], skesks: &[SKESK],
                      _sym_algo: Option<SymmetricAlgorithm>,
                      mut decrypt: D) -> Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
        {
            skesks[0].decrypt(&Password::from(NEEDLE))
                .map(|(algo, session_key)| decrypt(algo, &session_key))?;
            Ok(None)
        }
    }

    let h = Helper {};
    let mut v = DecryptorBuilder::from_bytes(ciphertext)?
        .with_policy(p, None, h)?;

    let mut content = Vec::new();
    v.read_to_end(&mut content)?;
    assert_eq!(content, b"Hello world.");
    Ok(())
}

fn main() {
    let test = std::env::args().nth(1)
        .expect("give the name of the test case as first argument");

    eprintln!("{}: running test", test);
    match test.as_str() {
        "test_aes_256_encryption" => {
            for _ in 0..(N + 1) / 2 {
                test_aes_256_encryption().unwrap();
            }
            scan(&test).unwrap();
            return;
        },
        "test_aes_256_decryption" => {
            let ciphertext = test_aes_256_encryption().unwrap();
            for _ in 0..(N + 1) / 2 {
                test_aes_256_decryption(&ciphertext).unwrap();
            }
            scan(&test).unwrap();
            return;
        },
        _ => (),
    }

    for _ in 0..N {
        match test.as_str() {
            "clean_basecase" => clean_basecase(),
            "leak_basecase" => leak_basecase(),
            "test_memzero" => test_memzero(),
            "test_libc_memset" => test_libc_memset(),
            "test_protected" => test_protected(),
            "test_protected_mpi" => test_protected_mpi(),
            "test_session_key" => test_session_key(),
            "test_encrypted" => test_encrypted(),
            "test_password" => test_password(),
            "test_ed25519" => test_ed25519(),
            a => panic!("unknown test case {:?}", a),
        }
    }

    scan(&test).unwrap();
}

fn scan(name: &str) -> Result<()> {
    let mut found_secret = false;
    let mut sink = std::io::stderr();
    for map in Map::iter()? {
        let map = map?;
        if map.read && map.write {
            let mut header_printed = false;
            //dbg!(&map);
            let view = map.as_bytes()?;
            //eprintln!("{}", hex::encode(&view[..32]));
            const CS: usize = 16;
            for (i, c) in view.chunks(CS).enumerate() {
                if c.iter().filter(|&b| *b == N0).count() > 7 {
                    found_secret = true;

                    if ! header_printed {
                        eprintln!("{}: {} bytes", map.pathname, map.len);
                        header_printed = true;
                    }

                    let mut d = hex::Dumper::with_offset(
                        &mut sink, "", map.start as usize + i * CS);
                    d.write_labeled(c, |_, buf| {
                        let mut s = String::with_capacity(16);
                        for b in buf {
                            assert!(N0 != b'!');
                            s.push(if *b == N0 {
                                '!'
                            } else {
                                '.'
                            });
                        }
                        Some(s)
                    })?;
                }
            }
        }
    }

    if found_secret {
        eprintln!("{}: secret leaked", name);
        std::process::exit(1);
    } else {
        eprintln!("{}: passed", name);
        Ok(())
    }
}

use std::{
    fs::File,
    io::{BufReader, BufRead},
};

#[derive(Debug)]
#[allow(dead_code)]
struct Map {
    start: u64,
    len: u64,
    read: bool,
    write: bool,
    execute: bool,
    offset: u64,
    device: String,
    inode: u64,
    pathname: String,
}

impl Map {
    fn iter() -> Result<impl Iterator<Item = Result<Map>>> {
        let f = File::open("/proc/self/maps")?;
        let f = BufReader::new(f);
        Ok(f.lines().filter_map(|l| l.ok()).map(Self::parse_line))
    }

    fn parse_line(l: String) -> Result<Self> {
        let f = l.splitn(6, ' ').collect::<Vec<_>>();
        let a = f[0].splitn(2, '-').collect::<Vec<_>>();
        let parse_hex = |s| -> Result<u64> {
            let b = hex::decode(s)?;
            let mut a = [0; 8]; // XXX word size <= u64
            let l = a.len().min(b.len());
            a[8 - l..].copy_from_slice(&b[..l]);
            Ok(u64::from_be_bytes(a))
        };
        let start = parse_hex(&a[0])?;
        let end = parse_hex(&a[1])?;
        assert!(start <= end);

        Ok(Map {
            start,
            len: end - start,
            read: f[1].as_bytes()[0] == b'r',
            write: f[1].as_bytes()[1] == b'w',
            execute: f[1].as_bytes()[2] == b'x',
            offset: parse_hex(&f[2])?,
            device: f[3].into(),
            inode: f[4].parse()?,
            pathname: f[5].trim_start().into(),
        })
    }

    fn as_bytes(&self) -> Result<&[u8]> {
        if self.read {
            let s = unsafe {
                std::slice::from_raw_parts(self.start as usize as *const _,
                                           self.len as usize)
            };
            Ok(s)
        } else {
            Err(anyhow::anyhow!("No read permissions"))
        }
    }
}
