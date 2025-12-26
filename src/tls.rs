// Stream wrapper.

use rustls_pemfile::{certs, private_key};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    client::danger::{ServerCertVerified, ServerCertVerifier},
};
use tokio_rustls::TlsAcceptor;

use crate::config::get_config;
use crate::errors::Error;

// TLS
pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid cert"))
}

pub fn load_key(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    private_key(&mut reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no private key found")
    })
}

pub struct Tls {
    pub acceptor: TlsAcceptor,
}

impl Tls {
    pub fn new() -> Result<Self, Error> {
        let config = get_config();

        let certs = match load_certs(Path::new(&config.general.tls_certificate.unwrap())) {
            Ok(certs) => certs,
            Err(_) => return Err(Error::TlsError),
        };

        let key = match load_key(Path::new(&config.general.tls_private_key.unwrap())) {
            Ok(key) => key,
            Err(_) => return Err(Error::TlsError),
        };

        let config = match rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))
        {
            Ok(c) => c,
            Err(_) => return Err(Error::TlsError),
        };

        Ok(Tls {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}

#[derive(Debug)]
pub struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
