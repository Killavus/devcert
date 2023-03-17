use crate::error::AppResult;

use rcgen::{Certificate as RcgenCertificate, CertificateParams, DistinguishedName, IsCa};
use time::{ext::NumericalDuration, OffsetDateTime};

pub struct CACertificate(rcgen::Certificate);

pub trait Certificate {
    fn key_pem(&self) -> String;
    fn cert_pem(&self) -> AppResult<String>;
    fn is_root_cert(&self) -> bool;
}

impl Certificate for CACertificate {
    fn key_pem(&self) -> String {
        self.0.serialize_private_key_pem()
    }

    fn cert_pem(&self) -> AppResult<String> {
        Ok(self.0.serialize_pem()?)
    }

    fn is_root_cert(&self) -> bool {
        true
    }
}

pub fn create_root_ca_certificate() -> AppResult<CACertificate> {
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

    Ok(CACertificate(RcgenCertificate::from_params(params)?))
}
