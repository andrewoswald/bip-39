extern crate crypto;

use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::Mac;
use crypto::pbkdf2;
use crypto::sha2::{Sha256, Sha512};
use MnemonicListSize::*;

// Enforce the list sizes by way of an enum.
pub enum MnemonicListSize {
    Twelve = 12,
    Fifteen = 15,
    Eighteen = 18,
    TwentyOne = 21,
    TwentyFour = 24,
}

// "impl" blocks define methods:
impl MnemonicListSize {
    pub fn from(size: usize) -> Result<MnemonicListSize, &'static str> {
        let mnemonic_list_size = match size {
            12 => Twelve,
            15 => Fifteen,
            18 => Eighteen,
            21 => TwentyOne,
            24 => TwentyFour,
            _ => return Err("Invalid mnemonic word list size."),
        };

        // The lack of semicolon below is how "expression" code returns its result:
        Ok(mnemonic_list_size)
    }
}

// When used as a library in external rust code, the Config is the way to safely invoke functionality here.
// 'Config' is a "named-field" struct; while its types are both String, structs can contain mixed types.
pub struct Config {
    // Any guesses as to what 'pub' in the struct definition as well as below means?
    pub mnemonic: String,
    // Note: no 'pub' on 'salt', thus forcing construction to be done from its impl, below.
    salt: String,
}

impl Config {
    pub fn generate_from(word_list_size: MnemonicListSize, passphrase: String) -> Config {
        Config {
            // Discuss get_mnemonic function:
            mnemonic: get_mnemonic(word_list_size),
            salt: get_salt(passphrase),
        }
    }

    pub fn new(mnemonic: String, word_list_size: MnemonicListSize, passphrase: String) -> Config {
        // Note that 'word_list_size' of enum type MnemoncListSize can be converted to a 'usize' here:
        assert_eq!(mnemonic.split(' ').count(), word_list_size as usize);

        Config {
            // Handy way to create your struct if variable name(s) match(es):
            mnemonic,
            salt: get_salt(passphrase),
        }
    }
}

pub fn generate_seed(config: Config) -> String {
    let mut output = [0; 64];
    let mut mac = Hmac::new(Sha512::new(), config.mnemonic.as_bytes());
    pbkdf2::pbkdf2(&mut mac, config.salt.as_bytes(), 2048, &mut output);
    // The '..' means use the entire byte array "slice":
    hex::encode(&output[..])
}

// Refer to BIP-32 requirements (Serialization format):
pub fn generate_root_key(seed: &[u8]) -> String {
    assert!(seed.len() == 64);
    let mut output = [0; 64];
    let mut mac = Hmac::new(Sha512::new(), b"Bitcoin seed");
    mac.input(seed);
    mac.raw_result(&mut output);
    // 'il' is the "master secret key" and 'ir' is the "master chain code"
    let (il, ir) = output.split_at(32);

    // Serialize the master key:
    let mut data = Vec::with_capacity(82);
    // Initial four bytes are for "mainnet private key":
    data.extend(&[4, 136, 173, 228, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    data.extend(ir);
    data.extend(&[0]);
    data.extend(il);

    // Double hash the data to get the last four bytes:
    let mut checksum_digest = [0; 32];
    let mut hasher = Sha256::new();
    hasher.input(&data);
    hasher.result(&mut checksum_digest);
    hasher.reset();
    hasher.input(&checksum_digest);
    hasher.result(&mut checksum_digest);
    data.extend(&checksum_digest[..4]);

    // Base58 will encode the master key to start with "xprv":
    bs58::encode(data).into_string()
}

// The spec calls for the salt to be prefixed by 'mnemonic'.
// The 'passphrase' is entirely optional.
fn get_salt(passphrase: String) -> String {
    //String::from("mnemonic") + passphrase.as_str()
    //"mnemonic".to_string() + &passphrase
    format!("mnemonic{}", passphrase)
}

fn get_mnemonic(word_list_size: MnemonicListSize) -> String {
    // Create 32 bytes of random values (rust's arrays must be defined at compile time):
    let rand_seq = rand::random::<[u8; 32]>();

    // Given the word_list_size, we'll define our 'entropy' as a slice of the above 'rand_seq':
    let entropy = get_entropy(&word_list_size, &rand_seq);

    let entropy_bits_len = entropy.len() * 8;
    let mut terms = String::new();

    let mut bits_consumed = 0;
    let mut term_index: usize = 0;
    // Declare the 2,048 word list:
    let word_list = get_word_list();

    // Accumulate the mnemonic terms from the entropy:
    while bits_consumed < entropy_bits_len {
        let remaining_term_bits = 11 - (bits_consumed % 11);
        let high_pos = 8 - (bits_consumed % 8);
        let low_bound = if remaining_term_bits >= high_pos {
            0 // drain the remaining bits
        } else {
            high_pos - remaining_term_bits
        };

        shift(
            high_pos,
            low_bound,
            &mut term_index,
            entropy[bits_consumed / 8],
        );

        bits_consumed += high_pos - low_bound;

        // If we've accumulated 11 bits, it's time to get the mnemonic from the word list and add it to the terms:
        if bits_consumed % 11 == 0 {
            //print!("{:011b}", term_index);
            // You can treat Vector access as you would for an array:
            append_term(word_list[term_index], &mut terms);
            term_index = 0
        }
    }

    let checksum_byte = get_checksum_byte(entropy);
    //println!("\nchecksum_byte: {:08b}", checksum_byte);

    // Declaration by way of match:
    let checksum_low_bound = match word_list_size {
        Twelve => 4,
        Fifteen => 3,
        Eighteen => 2,
        TwentyOne => 1,
        TwentyFour => 0,
    };

    // Assign the final term's bits to the 'term_index' using the 'checksum_byte':
    shift(8, checksum_low_bound, &mut term_index, checksum_byte);

    append_term(word_list[term_index], &mut terms);

    terms
}

fn append_term(term: &str, mnemonic: &mut String) {
    if mnemonic.is_empty() == false {
        *mnemonic += " "
    }
    *mnemonic += term
}

// The 'a here is a "lifetime"; the function's output needs to live as long as the input here:
fn get_entropy<'a>(word_list_size: &MnemonicListSize, rand_seq: &'a [u8]) -> &'a [u8] {
    match word_list_size {
        // The "..#" is a "slice" of the input data:
        Twelve => &rand_seq[..16],
        Fifteen => &rand_seq[..20],
        Eighteen => &rand_seq[..24],
        TwentyOne => &rand_seq[..28],
        TwentyFour => &rand_seq[..32],
    }
}

fn shift(high_pos: usize, low_bound: usize, term_index: &mut usize, byte: u8) {
    // reverse the order, going from high_pos to low_bound:
    for i in (low_bound..high_pos).rev() {
        // shift the term_index as we're consuming bits:
        // the '*' derefs the 'term_index', thus mutating its actual contents:
        *term_index <<= 1;

        // if we bitwise & the shifted bit on the entropy byte, increment the term_index' value:
        if 1 << i & byte > 0 {
            *term_index += 1
        }
    }
}

fn get_word_list() -> Vec<&'static str> {
    // 'cfg!' macro is for compile time boolean evaluation:
    // 'feature' is used by cargo for conditional building:
    let contents = if cfg!(feature = "chinese_traditional") {
        include_str!("../wordlists/chinese_traditional.txt")
    } else if cfg!(feature = "czech") {
        include_str!("../wordlists/czech.txt")
    } else if cfg!(feature = "japanese") {
        include_str!("../wordlists/japanese.txt")
    } else if cfg!(feature = "korean") {
        include_str!("../wordlists/korean.txt")
    } else if cfg!(feature = "spanish") {
        include_str!("../wordlists/spanish.txt")
    } else if cfg!(feature = "chinese_simplified") {
        include_str!("../wordlists/chinese_simplified.txt")
    } else if cfg!(feature = "french") {
        include_str!("../wordlists/french.txt")
    } else if cfg!(feature = "italian") {
        include_str!("../wordlists/italian.txt")
    } else if cfg!(feature = "portuguese") {
        include_str!("../wordlists/portuguese.txt")
    } else {
        include_str!("../wordlists/english.txt")
    };

    // get an iterator from our word list of its lines and collect them into a Vector:
    contents.lines().collect::<Vec<&str>>()
}

fn get_checksum_byte(entropy: &[u8]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.input(entropy);
    // Arrays may be created initialized w/ a value and the length:
    let mut digest_out = [0; 32];
    hasher.result(&mut digest_out);
    digest_out[0]
}
