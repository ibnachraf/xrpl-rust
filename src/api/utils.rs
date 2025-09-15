use bs58::Alphabet;
use sha2::{Digest, Sha256, Sha512};
use strum::IntoEnumIterator;

use crypto_bigint::Encoding;
use crypto_bigint::U256;
use ripemd::Ripemd160;
use strum_macros::Display;
use strum_macros::EnumIter;

use secp256k1::Scalar;

pub const ED25519_PREFIX: &str = "ED";
pub const SHA512_HASH_LENGTH: usize = 32;
pub const ACCOUNT_ID_LENGTH: usize = 20;
pub(crate) const CLASSIC_ADDRESS_PREFIX: [u8; 1] = [0x0];
pub const SEED_LENGTH: usize = 16;
pub const XRPL_ALPHABET: Alphabet = *bs58::Alphabet::RIPPLE;
/// value is 33; Seed value (for secret keys) (16 bytes)
pub(crate) const FAMILY_SEED_PREFIX: [u8; 1] = [0x21];
/// [1, 225, 75]
pub(crate) const ED25519_SEED_PREFIX: [u8; 3] = [0x01, 0xE1, 0x4B];
pub(crate) const SECP256K1_SEQUENCE_SIZE: u32 = 4;
pub(crate) const SECP256K1_SEQUENCE_MAX: u64 = u64::pow(256, SECP256K1_SEQUENCE_SIZE);
pub(crate) const SECP256K1_KEY_LENGTH: usize = 66;
pub(crate) const SECP256K1_INTERMEDIATE_KEYPAIR_PADDING: [u8; 4] = [0, 0, 0, 0];
pub const SECRET_KEY_LENGTH: usize = 32;
pub(crate) const CLASSIC_ADDRESS_LENGTH: u8 = 20;

#[derive(Debug, Display)]
pub enum XRPLCoreException {
    UnknownSeedEncoding,
    UnexpectedPayloadLength,
    InvalidPrefix,
    UnsupportedValidatorAlgorithm,
    InvalidSecret,
}

pub type XRPLCoreResult<T, E = XRPLCoreException> = core::result::Result<T, E>;

#[macro_export]
macro_rules! skip_err {
    ($result:expr) => {
        match $result {
            Ok(value) => Ok(value),
            Err(_) => continue,
        }
    };
}

#[derive(Debug, EnumIter, Default)]
pub enum CryptoAlgorithm {
    #[default]
    ED25519,
    SECP256K1,
}

pub trait CryptoImplementation {
    /// Derives a key pair for use with the XRP Ledger
    /// from a seed value.
    fn derive_keypair(
        &self,
        decoded_seed: &[u8],
        is_validator: bool,
    ) -> XRPLCoreResult<(String, String)>;
}

pub struct Secp256k1;
impl CryptoImplementation for Secp256k1 {
    fn derive_keypair(
        &self,
        decoded_seed: &[u8],
        is_validator: bool,
    ) -> XRPLCoreResult<(String, String)> {
        let (root_public, root_secret) = Self::_derive_part(decoded_seed, Secp256k1Phase::Root)?;
        if is_validator {
            Ok(Secp256k1::_format_keys(root_public, root_secret))
        } else {
            let (mid_public, mid_secret) =
                Self::_derive_part(&root_public.serialize(), Secp256k1Phase::Mid)?;
            let (final_public, final_secret) =
                Self::_derive_final(root_public, root_secret, mid_public, mid_secret)?;

            Ok(Secp256k1::_format_keys(final_public, final_secret))
        }
    }
}
#[derive(Debug, PartialEq)]
pub(crate) enum Secp256k1Phase {
    Root,
    Mid,
}

impl Secp256k1 {
    /// Derive the final public/private keys.
    fn _derive_final(
        root_public: secp256k1::PublicKey,
        root_private: secp256k1::SecretKey,
        mid_public: secp256k1::PublicKey,
        mid_private: secp256k1::SecretKey,
    ) -> XRPLCoreResult<(secp256k1::PublicKey, secp256k1::SecretKey)> {
        let wrapped_private = root_private.add_tweak(&Scalar::from(mid_private)).unwrap();
        let wrapped_public = root_public.combine(&mid_public).unwrap();

        Ok((wrapped_public, wrapped_private))
    }

    fn _private_key_to_str(key: secp256k1::SecretKey) -> String {
        hex::encode_upper(key.as_ref())
    }

    fn _public_key_to_str(key: secp256k1::PublicKey) -> String {
        hex::encode_upper(key.serialize())
    }

    fn _format_key(keystr: &str) -> String {
        format!("{keystr:0>SECP256K1_KEY_LENGTH$}")
    }

    fn _format_keys(
        public: secp256k1::PublicKey,
        private: secp256k1::SecretKey,
    ) -> (String, String) {
        (
            Secp256k1::_format_key(&Secp256k1::_public_key_to_str(public)),
            Secp256k1::_format_key(&Secp256k1::_private_key_to_str(private)),
        )
    }
    fn _derive_part(
        bytes: &[u8],
        phase: Secp256k1Phase,
    ) -> XRPLCoreResult<(secp256k1::PublicKey, secp256k1::SecretKey)> {
        let raw_private = Self::_get_secret(bytes, &phase)?;
        let secp = secp256k1::Secp256k1::new();
        let wrapped_private = secp256k1::SecretKey::from_slice(&raw_private).unwrap();
        let wrapped_public = secp256k1::PublicKey::from_secret_key(&secp, &wrapped_private);

        Ok((wrapped_public, wrapped_private))
    }

    fn _is_secret_valid(key: [u8; u32::BITS as usize]) -> bool {
        let key_bytes = U256::from_be_bytes(key);
        key_bytes >= U256::ONE
            && key_bytes <= U256::from_be_bytes(secp256k1::constants::CURVE_ORDER)
    }

    fn _candidate_merger(input: &[u8], candidate: &[u8], phase: &Secp256k1Phase) -> Vec<u8> {
        if phase == &Secp256k1Phase::Root {
            [input, candidate].concat()
        } else {
            [input, &SECP256K1_INTERMEDIATE_KEYPAIR_PADDING, candidate].concat()
        }
    }

    fn _get_secret(
        input: &[u8],
        phase: &Secp256k1Phase,
    ) -> XRPLCoreResult<[u8; SHA512_HASH_LENGTH]> {
        for raw_root in 0..SECP256K1_SEQUENCE_MAX {
            let root = (raw_root as u32).to_be_bytes();
            let candidate = sha512_first_half(&Self::_candidate_merger(input, &root, phase));

            if Self::_is_secret_valid(candidate) {
                return Ok(candidate);
            } else {
                continue;
            }
        }

        Err(XRPLCoreException::InvalidSecret)
    }
}

impl Ed25519 {
    /// Hex encode the private key.
    fn _private_key_to_str(key: ed25519_dalek::SecretKey) -> String {
        hex::encode(key)
    }

    /// Hex encode the public key.
    fn _public_key_to_str(key: ed25519_dalek::VerifyingKey) -> String {
        hex::encode(key.as_ref())
    }

    /// Format a provided key.
    /// TODO Determine security implications
    fn _format_key(keystr: &str) -> String {
        format!("{}{}", ED25519_PREFIX, keystr.to_uppercase())
    }

    /// Format the public and private keys.
    fn _format_keys(
        public: ed25519_dalek::VerifyingKey,
        private: ed25519_dalek::SecretKey,
    ) -> (String, String) {
        (
            Ed25519::_format_key(&Ed25519::_public_key_to_str(public)),
            Ed25519::_format_key(&Ed25519::_private_key_to_str(private)),
        )
    }
}

pub struct Ed25519;

impl CryptoImplementation for Ed25519 {
    fn derive_keypair(
        &self,
        decoded_seed: &[u8],
        is_validator: bool,
    ) -> XRPLCoreResult<(String, String)> {
        if is_validator {
            Err(XRPLCoreException::UnsupportedValidatorAlgorithm)
        } else {
            let raw_private = sha512_first_half(decoded_seed);
            let private: [u8; SECRET_KEY_LENGTH] = ed25519_dalek::SecretKey::from(raw_private);
            let signing_key: ed25519_dalek::SigningKey = private.into();
            let public = (&signing_key).into();

            Ok(Ed25519::_format_keys(public, private))
        }
    }
}

pub fn decode_base58(b58_string: &str, prefix: &[u8]) -> Result<Vec<u8>, XRPLCoreException> {
    let prefix_len = prefix.len();
    let decoded = bs58::decode(b58_string)
        .with_alphabet(&XRPL_ALPHABET)
        .with_check(None)
        .into_vec()
        .unwrap();

    if &decoded[..prefix_len] != prefix {
        Err(XRPLCoreException::InvalidPrefix)
    } else {
        Ok(decoded[prefix_len..].to_vec())
    }
}

pub fn encode_base58(
    bytestring: &[u8],
    prefix: &[u8],
    expected_length: Option<usize>,
) -> Result<String, XRPLCoreException> {
    if expected_length != Some(bytestring.len()) {
        Err(XRPLCoreException::UnexpectedPayloadLength)
    } else {
        let mut payload = vec![];

        payload.extend_from_slice(prefix);
        payload.extend_from_slice(bytestring);

        Ok(bs58::encode(payload)
            .with_alphabet(&XRPL_ALPHABET)
            .with_check()
            .into_string())
    }
}

pub fn sha512_first_half(message: &[u8]) -> [u8; SHA512_HASH_LENGTH] {
    let mut sha512 = Sha512::new();

    sha512.update(message);
    sha512.finalize()[..SHA512_HASH_LENGTH]
        .try_into()
        .expect("Invalid slice length")
}

fn _get_algorithm_engine(algo: CryptoAlgorithm) -> Box<dyn CryptoImplementation> {
    match algo {
        CryptoAlgorithm::ED25519 => Box::new(Ed25519),
        CryptoAlgorithm::SECP256K1 => Box::new(Secp256k1),
    }
}

pub fn derive_keypair(seed: &str, validator: bool) -> XRPLCoreResult<(String, String)> {
    let (decoded_seed, algorithm) = decode_seed(seed)?;
    let module = _get_algorithm_engine(algorithm);
    let (public, private) = module.derive_keypair(&decoded_seed, validator)?;
    // let signature = sign(SIGNATURE_VERIFICATION_MESSAGE, &private)?;
    Ok((public, private))
}

fn _algorithm_to_prefix<'a>(algo: &CryptoAlgorithm) -> &'a [u8] {
    match algo {
        CryptoAlgorithm::ED25519 => &ED25519_SEED_PREFIX,
        CryptoAlgorithm::SECP256K1 => &FAMILY_SEED_PREFIX,
    }
}

pub fn decode_seed(seed: &str) -> XRPLCoreResult<([u8; SEED_LENGTH], CryptoAlgorithm)> {
    let mut result: Option<XRPLCoreResult<Vec<u8>>> = None;
    let mut algo: Option<CryptoAlgorithm> = None;

    for a in CryptoAlgorithm::iter() {
        let decode = decode_base58(seed, _algorithm_to_prefix(&a));
        result = Some(skip_err!(decode));
        algo = Some(a);
    }

    match result {
        Some(Ok(val)) => {
            let n = val.len();
            println!("Decoded seed length: {}", n);
            let decoded: [u8; SEED_LENGTH] = val.try_into().unwrap();
            Ok((decoded, algo.expect("decode_seed")))
        }
        Some(Err(_)) | None => Err(XRPLCoreException::UnknownSeedEncoding),
    }
}

pub fn derive_classic_address_from_public_key(public_key: &str) -> XRPLCoreResult<String> {
    let account_id = get_account_id(&hex::decode(public_key).unwrap());
    encode_classic_address(&account_id)
}

pub fn get_account_id(public_key: &[u8]) -> [u8; ACCOUNT_ID_LENGTH] {
    let mut sha256 = Sha256::new();
    let mut ripemd160 = Ripemd160::new();

    sha256.update(public_key);
    ripemd160.update(sha256.finalize());

    ripemd160.finalize()[..ACCOUNT_ID_LENGTH]
        .try_into()
        .expect("Invalid slice length")
}

pub fn encode_classic_address(bytestring: &[u8]) -> XRPLCoreResult<String> {
    Ok(encode_base58(
        bytestring,
        &CLASSIC_ADDRESS_PREFIX,
        Some(CLASSIC_ADDRESS_LENGTH.into()),
    )?)
}

pub fn derive_classic_address_from_seed(seed: &str) -> XRPLCoreResult<String> {
    let (public, _) = derive_keypair(seed, false)?;
    derive_classic_address_from_public_key(&public)
}

#[test]
fn test_derive_classic_address() {
    let seed = "sn3nxiW7v8KXzPzAqzyHXbSSKNuN9";
    let address = derive_classic_address_from_seed(seed).unwrap();
    assert!(address == "rMCcNuTcajgw7YTgBy1sys3b89QqjUrMpH");
}
