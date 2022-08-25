
use std::env;
use openssl::nid::Nid;
use openssl::error::ErrorStack;

use openssl::sign::{Signer, Verifier};
use openssl::ec::{EcKey, EcGroup, EcPoint};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;


fn get_ec_point() -> Result<EcPoint, ErrorStack> {
   let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
   let point = EcPoint::new(&group)?;
   Ok(point)
}

//NID_X9_62_prime256v1

fn main() {
    println!("Hello, world!");
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x1_01_01_00_0 {
            println!("cargo:rustc-cfg=openssl111");
        }
    }


    // ec key
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let keypair = EcKey::generate(&group).unwrap();
    let keypair = PKey::from_ec_key(keypair).unwrap();

    // data to sign
    let data = b"hello, world!";

    // hash: sha-256
    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    let buf_size = signer.len().unwrap();  // Computes an upper bound on the signature length.
    println!("buffer size {}", buf_size);  // 72
    let mut buf: [u8; 72] = [0; 72];

    // sign
    let exact_bytes = signer.sign_oneshot(&mut buf, data).unwrap(); //the number of bytes written.
    println!("{}", exact_bytes); // 70


    // Sign the data
    let mut signer = Signer::new(MessageDigest::sha512(), &keypair).unwrap();
    signer.update(data).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    println!("ECDSA signatur: {:?}", signature);
    
    println!("Hello, world!");
    let data = b"hello, world!";

    // Verify the data
    let mut verifier = Verifier::new(MessageDigest::sha512(), &keypair).unwrap();
    verifier.update(data).unwrap();

    let result = verifier.verify(&signature).unwrap();

    if result {
        println!("verify OK :-)");
    }
    else {
        println!("verify KO :-(");
    }



}
