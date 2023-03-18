use std::net::IpAddr;

use crate::{certstore::CertStore, error::AppResult};

use rcgen::{
    Certificate as RcgenCertificate, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose,
    IsCa, KeyUsagePurpose, SanType,
};
use time::{ext::NumericalDuration, OffsetDateTime};

pub enum Certificate<'cert> {
    RootCertificate(rcgen::Certificate),
    HostCertificate {
        hostname: String,
        host: rcgen::Certificate,
        root: &'cert rcgen::Certificate,
    },
}

impl<'cert> Certificate<'cert> {
    fn inner(&self) -> &rcgen::Certificate {
        match self {
            Self::RootCertificate(cert) => cert,
            Self::HostCertificate { host, .. } => host,
        }
    }

    pub fn cert_der(&self) -> AppResult<Vec<u8>> {
        Ok(self.inner().serialize_der()?)
    }

    pub fn key_pem(&self) -> String {
        self.inner().serialize_private_key_pem()
    }

    pub fn cert_pem(&self) -> AppResult<String> {
        match self {
            Self::RootCertificate(cert) => Ok(cert.serialize_pem()?),
            Self::HostCertificate { host, root, .. } => Ok(host.serialize_pem_with_signer(root)?),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::RootCertificate(_) => CertStore::ROOT_CERT_NAME,
            Self::HostCertificate { hostname, .. } => hostname,
        }
    }
}

pub fn create_root_ca_certificate<'cert>() -> AppResult<Certificate<'cert>> {
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

        params.not_before = OffsetDateTime::now_utc()
            .checked_sub(1.days())
            .expect("certificate date is in bounds");
        params.not_after = OffsetDateTime::now_utc()
            .checked_add(maximum_safe_ca_cert_validity_duration)
            .expect("certificate date is in bounds");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params
    };

    Ok(Certificate::RootCertificate(RcgenCertificate::from_params(
        params,
    )?))
}

pub fn create_host_certificate<'cert>(
    host: &str,
    root_cert: &'cert Certificate,
) -> AppResult<Certificate<'cert>> {
    let san = match host.parse::<IpAddr>() {
        Ok(ip_addr) => SanType::IpAddress(ip_addr),
        Err(_) => SanType::URI(host.to_owned()),
    };

    let params = {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.distinguished_name = {
            use rcgen::DnType;
            let mut dn = DistinguishedName::new();
            dn.push(DnType::OrganizationName, "devcert");
            dn.push(DnType::CountryName, "US");
            dn.push(
                DnType::LocalityName,
                &format!("devcert Certificate for {}", host),
            );
            dn
        };
        params.subject_alt_names = vec![san];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params
    };

    Ok(Certificate::HostCertificate {
        host: rcgen::Certificate::from_params(params)?,
        root: root_cert.inner(),
        hostname: host.to_owned(),
    })
}
