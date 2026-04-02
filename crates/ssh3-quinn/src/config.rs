use std::fmt;
use std::sync::Arc;

use quinn::{
    ClientConfig, ServerConfig,
    crypto::rustls::{NoInitialCipherSuite, QuicClientConfig},
};
use rcgen::CertifiedKey;
use rustls::{
    RootCertStore,
    client::VerifierBuilderError,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

#[derive(Debug)]
pub enum ConfigError {
    Rcgen(rcgen::Error),
    Rustls(rustls::Error),
    Verifier(VerifierBuilderError),
    NoInitialCipherSuite(NoInitialCipherSuite),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rcgen(err) => write!(f, "{err}"),
            Self::Rustls(err) => write!(f, "{err}"),
            Self::Verifier(err) => write!(f, "{err}"),
            Self::NoInitialCipherSuite(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rcgen(err) => Some(err),
            Self::Rustls(err) => Some(err),
            Self::Verifier(err) => Some(err),
            Self::NoInitialCipherSuite(err) => Some(err),
        }
    }
}

impl From<rcgen::Error> for ConfigError {
    fn from(value: rcgen::Error) -> Self {
        Self::Rcgen(value)
    }
}

impl From<rustls::Error> for ConfigError {
    fn from(value: rustls::Error) -> Self {
        Self::Rustls(value)
    }
}

impl From<VerifierBuilderError> for ConfigError {
    fn from(value: VerifierBuilderError) -> Self {
        Self::Verifier(value)
    }
}

impl From<NoInitialCipherSuite> for ConfigError {
    fn from(value: NoInitialCipherSuite) -> Self {
        Self::NoInitialCipherSuite(value)
    }
}

pub fn server_config_with_single_cert(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, ConfigError> {
    Ok(ServerConfig::with_single_cert(cert_chain, key)?)
}

pub fn client_config_with_roots(roots: RootCertStore) -> Result<ClientConfig, ConfigError> {
    Ok(ClientConfig::with_root_certificates(Arc::new(roots))?)
}

pub fn client_config_for_certificate(
    server_certificate: CertificateDer<'static>,
) -> Result<ClientConfig, ConfigError> {
    let mut roots = RootCertStore::empty();
    roots.add(server_certificate)?;
    client_config_with_roots(roots)
}

pub fn client_config_with_webpki_roots() -> Result<ClientConfig, ConfigError> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config_with_roots(roots)
}

pub fn client_config_insecure() -> Result<ClientConfig, ConfigError> {
    let client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        client_config,
    )?)))
}

pub fn self_signed_server_config(
    subject_alt_names: Vec<String>,
) -> Result<(ServerConfig, CertificateDer<'static>), ConfigError> {
    let CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let certificate = cert.der().clone();
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let server_config = server_config_with_single_cert(vec![certificate.clone()], private_key)?;
    Ok((server_config, certificate))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ))
    }
}

impl ServerCertVerifier for SkipServerVerification {
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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
