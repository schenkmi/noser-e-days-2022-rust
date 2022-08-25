//
// # generate a private key for a curve
// openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
//
// # generate corresponding public key
// openssl ec -in private-key.pem -pubout -out public-key.pem
//

use std::io::Read;
use std::fs::File;
use std::fs;
use std::path::Path;

use openssl::nid::Nid;
use openssl::error::ErrorStack;
use openssl::pkey::Private;
use openssl::sign::{Signer, Verifier};
use openssl::ec::{EcKey, EcGroup};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;

fn get_file_as_byte_vec(filename: &String) -> Vec<u8> {
    let mut f = File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");
    return buffer;
}

fn create_ec_keypair() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let keypair = EcKey::generate(&group).unwrap();

    // public key as pem
    let pub_key = keypair.public_key_to_pem().unwrap();
    // convert pem vector to string
    let s = String::from_utf8(pub_key).expect("Found invalid UTF-8");
    println!("public key = {}", s);
    fs::write("public.pem", s).expect("Unable to write file");

    // private key as pem
    let priv_key = keypair.private_key_to_pem().unwrap();
    // convert pem vector to string
    let s = String::from_utf8(priv_key).expect("Found invalid UTF-8");
    println!("private key = {}", s); 
    fs::write("private.pem", s).expect("Unable to write file");
}

fn get_ec_keypair() -> Result<EcKey<Private>, ErrorStack> {
    if !Path::new("private.pem").exists() {
        println!("private.pem not exist, creating it");
        create_ec_keypair();
    }

    // private PEM contains public and private key
    let data = fs::read("private.pem").expect("Unable to read file");

    // convert Vec<u8> to &[u8]
    let c = &data[..];

    let keypair = EcKey::private_key_from_pem(c);

    return keypair;
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() > 1 {
        // &args[1] borrow
        let filename = &args[1];
        let filebin = get_file_as_byte_vec(filename);
        println!("file data: {:?}", filebin);
    }

    // data to sign
    let data = b"hello, world!";

    // get or create ec keypair
    let ec_key_pair = get_ec_keypair().unwrap();
    let private_key = PKey::from_ec_key(ec_key_pair).unwrap();

    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha512(), &private_key).unwrap();
    signer.update(data).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    println!("ECDSA signatur: {:?}", signature);

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha512(), &private_key).unwrap();
    verifier.update(data).unwrap();

    let result = verifier.verify(&signature).unwrap();

    if result {
        println!("verify OK :-)");
    }
    else {
        println!("verify KO :-(");
    }

}
