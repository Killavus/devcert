use certstore::CertStore;

mod certgen;
mod certstore;
mod error;

fn main() {
    let ca_cert = certgen::create_root_ca_certificate().expect("certificate generation failed");
    let store = CertStore::try_default().expect("failed to access cert store");
    store.add(ca_cert).expect("failed to add root cert");
}
