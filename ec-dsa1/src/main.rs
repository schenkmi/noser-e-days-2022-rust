//
// # generate a private key for a curve
// openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem
//
// # generate corresponding public key
// openssl ec -in private-key.pem -pubout -out public-key.pem
//

use std::env;

use std::io::Write;
use std::io::Read;
use std::fs::File;
//use std::fs::Metadata;
use std::fs;

use openssl::nid::Nid;
use openssl::error::ErrorStack;
use openssl::pkey::Public;
use openssl::sign::{Signer, Verifier};
use openssl::ec::{EcKey, EcGroup, EcPoint};
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;


fn get_ec_point() -> Result<EcPoint, ErrorStack> {
   let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
   let point = EcPoint::new(&group)?;
   Ok(point)
}


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




    // let mut ctx = openssl::bn::BigNumContext::new().unwrap();

    // println!("private eckey = {:?}", key.private_key());

    // let pem = key.private_key_to_pem().unwrap();
    // println!("pem = {:?}", pem);

    // // convert pem vector to string
    // let s = String::from_utf8(pem).expect("Found invalid UTF-8");
    // println!("{}", s);


    // let bytes = key.public_key().to_bytes(&group,
    //     openssl::ec::PointConversionForm::COMPRESSED, &mut ctx).unwrap();

    // println!("public key = {:?}", bytes);

    // drop(key);
    // let public_key = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
    // let ec_key = EcKey::from_public_key(&group, &public_key).unwrap();

    // assert!(ec_key.check_key().is_ok());
}


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
    
    // no API to get pubkey
    //let pubkey: PKey<Public> = PKey::from_ec_key(keypair).unwrap();
    
  

    let pub_key = keypair.public_key_to_pem().unwrap();
     // convert pem vector to string
     let s = String::from_utf8(pub_key).expect("Found invalid UTF-8");

     println!("public key = {:?}", s);

    //println!("{:?}", str::from_utf8(pub_key.as_slice()).unwrap());


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

    // dump args
    //let command_line: std::env::Args = std::env::args(); 

    let args: Vec<_> = std::env::args().collect();

    if args.len() > 1 {
        // &args[1] borrow
        let filename = &args[1];

        let filebin = get_file_as_byte_vec(filename);

        println!("file data: {:?}", filebin);
    }

    for argument in args {
        println!("[{}]", argument);
    }

    create_ec_keypair();
}
