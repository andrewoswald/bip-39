extern crate bip_39;
extern crate hex;
extern crate rpassword;

use bip_39::Config;
use bip_39::MnemonicListSize;
use std::io;
use std::process;

// The idea for BIP-39 is to create a deterministic wallet seed by way of
// randomly generated words and an optional salt.
// The user is presented with the opportunity to recreate the seed from a
// list of previously generated mnemonic values (and optional salt) or to
// create everything from scratch.
fn main() {
    // 1) Instruct user that they can (A): create a seed from scratch or (B): recreate a seed.
    // 2) In either case, ask for and capture how many mnemonic words they intend to use: 12, 15, 18, 21, or 24.
    // 3) Ask for and capture if they're creating a new seed.
    // 4) Ask for and capture the optional passphrase.
    // 5) Ask for and capture passphrase confirmation from #4; retry if confirmation does not match original.
    // 6) Acquire mnemonic terms - if:
    //		'A' path (creating from scratch), generate mnemonic terms based on count captured in #2.
    //		'B' path (recreating), ask for and capture mnemonic terms.
    // 7) Create 'Config' struct using terms, terms count, and passphrase.
    // 8) Generate seed using Config from #7.
    // 9) Generate BIP-32 "root key" using seed from #8.

    // Stuff ending w/ '!' is a macro:
    // "A macro invocation is shorthand for an "expanded" syntactic form." - rust docs
    println!("You may create a new seed from scratch or recreate one from a previously generated mnemonic list.");
    println!("In either case, what size mnemonic word list should the seed be derived from? [12, 15, 18, 21, or 24]");

    // 'let' declares variables:
    let mnemonic_list_size = get_mnemonic_list_size();

    let is_new_seed = get_is_new_seed();

    let passphrase = get_passphrase();

    // Just another way to declare a local variable; notice no use of parenthesis:
    let config = if is_new_seed {
        // Our first struct - 'Config'
        let config = Config::generate_from(mnemonic_list_size, passphrase);
        println!("your BIP-39 mnemonic: {}", config.mnemonic);
        config
    } else {
        Config::new(get_mnemonic_terms(), mnemonic_list_size, passphrase)
    };

    let seed = bip_39::generate_seed(config);

    println!("your BIP-39 seed: {}", seed);

    let data = hex::decode(seed).unwrap();

    let root_key = bip_39::generate_root_key(&data);

    println!("your BIP-32 root key: {}", root_key)
}

fn get_mnemonic_terms() -> String {
    println!("In one line, separated by single spaces, please enter your ordered mnemonic terms:");
    let mut terms = String::new();

    io::stdin()
        .read_line(&mut terms)
        .expect("Failed to read mnemonic terms");

    terms.trim().to_string()
}

// 'fn' is a "function pointer":
fn get_mnemonic_list_size() -> MnemonicListSize {
    // 'mut' indicates that the variable is mutable; variables are immutable unless explicitly marked 'mut':
    let mut size = String::new(); // Creates a new String (kind of like a StringBuilder in Java).
                                  // The ::new is an 'associated function', kind of like a static method on a Java class.

    io::stdin()
        // '&mut' is a "borrow"; it's a "reference" to 'size'
        .read_line(&mut size) // this function returns a 'Result', which encapsulates the response; there is no 'null' in rust.
        // 'expect' is a function on Result; we'll panic w/ the given text if the Result resulted in an error:
        .expect("Failed to read response."); // (expect "unwraps" its value, but in this case, we've already established size in this scope)

    // 'match' compares values and executes code accordingly:
    let mnemonic_list_size = match size.trim().parse() {
        // 'unwrap_or_else' is another function on Result; it takes a closure:
        Ok(num) => MnemonicListSize::from(num).unwrap_or_else(|err| {
            eprintln!("Error: {}", err);
            process::exit(1)
        }),
        // '_' is a catch-all that tells the compiler we don't really care what might be in the Err enum:
        Err(_) => {
            eprintln!("Error: Unable to parse mnemonic word list size.");
            process::exit(1)
        }
    };

    mnemonic_list_size
}

// Pop quiz! Describe what's going on here:
fn get_is_new_seed() -> bool {
    let mut new_seed_response = String::new();
    println!("Are you creating a new seed? [Y/n]");
    io::stdin()
        .read_line(&mut new_seed_response)
        .expect("Failed to read response.");

    new_seed_response = new_seed_response.trim().to_lowercase();

    if new_seed_response.is_empty() || new_seed_response.starts_with('y') {
        true
    } else if new_seed_response.starts_with('n') {
        false
    } else {
        eprintln!("Abort.");
        process::exit(1)
    }
}

fn get_passphrase() -> String {
    // 'loop' here does exactly what you think it would:
    loop {
        // 'rpassword' is an external "crate" we're using for capturing passwords:
        let passphrase = rpassword::prompt_password_stdout("Passphrase (Optional): ").unwrap();
        let confirmation = rpassword::prompt_password_stdout("Confirm passphrase: ").unwrap();

        // '==' is a shorthand for the partialEq "trait" on String; traits basically resemble Java interfaces.
        if passphrase == confirmation {
            return passphrase;
        } else {
            eprintln!("Error: Passphrase and confirmation did not match.  Please try again.");
            continue;
        }
    }
}
