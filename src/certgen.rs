use crate::error::DevcertError;

use rcgen::{Certificate as RcgenCertificate, CertificateParams, DistinguishedName, IsCa};
use time::{ext::NumericalDuration, OffsetDateTime};

pub(crate) enum CertType {
    RootCa,
    Leaf,
}

pub struct Certificate(rcgen::Certificate, pub(crate) CertType);

impl Certificate {
    pub fn key_pem(&self) -> String {
        self.0.serialize_private_key_pem()
    }

    pub fn cert_pem(&self) -> Result<String, DevcertError> {
        Ok(self.0.serialize_pem()?)
    }
}

pub fn create_root_ca_certificate() -> Result<Certificate, DevcertError> {
    let params = {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = {
            use rcgen::DnType;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "devcert");
            dn.push(DnType::CountryName, "US");
            dn.push(
                DnType::LocalityName,
                "devcert Development Mode Certificates",
            );
            dn
        };
        

        // Taken from CA/Browser Forum Document: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.4.2.pdf
        let maximum_safe_ca_cert_validity_duration =
            (39 * 4).weeks().checked_sub(2.days()).unwrap();

        params.not_before = OffsetDateTime::now_utc().checked_sub(1.days()).unwrap();
        params.not_after = OffsetDateTime::now_utc()
            .checked_add(maximum_safe_ca_cert_validity_duration)
            .unwrap();
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
    };

    Ok(Certificate(
        RcgenCertificate::from_params(params)?,
        CertType::RootCa,
    ))
}
