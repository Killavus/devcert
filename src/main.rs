mod certgen;
mod error;

fn main() {
    let ca_cert = certgen::create_root_ca_certificate().expect("certificate generation failed");
}
