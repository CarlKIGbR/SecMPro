// SPDX-License-Identifier: AGPL-3.0-or-later
//! `transport::tls` — the direct-mode stream provider (spec §8.1, `docs/05` §7; ADR-051 Part 2; TEST-SPEC-M6
//! TLS-01…TLS-11, FZ-02).
//!
//! **What it is.** A [`StreamProvider`] that opens a TCP connection to `RelayRef.direct` and runs TLS 1.3 on it with
//! rustls over aws-lc-rs. The SecMP-LINK handshake and frames run unchanged inside (both modes carry identical
//! SecMP-LINK bytes, §8.1). TLS is a transport here and never a SecMP construction (CLAUDE.md §1.6).
//!
//! **The configuration** ([`client_config`]) is built explicitly with `ClientConfig::builder_with_provider` — never
//! from the process-default provider (TLS-10):
//! - the key exchange is restricted to `X25519MLKEM768` (CLAUDE.md §1.3: the one group, hybrid; no classical group, no
//!   fallback);
//! - TLS 1.3 only, checked when the configuration is built: rustls's `tls12` feature is enabled in the graph by other
//!   crates (`futures-rustls`), so the version list is asserted, not assumed;
//! - ALPN `secmp/1`, and a server that does not select it is refused before any SecMP byte;
//! - no resumption, no session tickets, no 0-RTT;
//! - no SNI (reviewer decision, WEISUNG M6-B-4 §0.3): one certificate per relay, so a host name would only be metadata
//!   on the wire;
//! - the server certificate is accepted iff the chain is exactly one certificate whose `SubjectPublicKeyInfo` hashes
//!   (SHA-256) to `RelayRef.direct.spki_sha256` ([`PinVerifier`], OPEN-M6-09 A). Names and dates are not consulted, and
//!   no CA store is used (`docs/05` §7: "Web PKI is not used"). The `CertificateVerify` signature is still checked with
//!   the certificate's key (TLS-07).
//!
//! **Fail closed.** A relay without a direct endpoint is [`Error::NoDirectEndpoint`]. Every TLS failure — pin, version,
//! group, ALPN, signature — is [`Error::Rejected`], with no detail. This provider is used only when the user chose
//! direct mode; it never stands in for Tor (CLAUDE.md §1.5).

use core::future::Future;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, NamedGroup, ProtocolVersion,
    SignatureScheme,
};
use secmp_crypto::ConstantTimeEq;
use secmp_proto::sizes::HASH_LEN;
use secmp_proto::wire::inv::RelayRef;
use tokio_rustls::TlsConnector;

use crate::driver::{Isolation, ProviderStream, StreamProvider};
use crate::error::{Error, Result};

/// The ALPN protocol of SecMP-LINK over TLS (spec §8.1).
pub const ALPN: &[u8] = b"secmp/1";

/// The one key-exchange group (IANA 0x11EC).
pub const GROUP: NamedGroup = NamedGroup::X25519MLKEM768;

/// The crypto provider of every SecMPro TLS configuration: aws-lc-rs with the key exchange restricted to
/// `X25519MLKEM768` (spec §8.1, `docs/05` §7). Shared by the client provider and the relay's direct listener.
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    let base = rustls::crypto::aws_lc_rs::default_provider();
    // TLS 1.3 cipher suites only: with rustls's `tls12` feature on in the graph, no TLS 1.2 suite remains to negotiate
    let cipher_suites = base
        .cipher_suites
        .iter()
        .copied()
        .filter(|s| s.version() == &rustls::version::TLS13)
        .collect();
    Arc::new(CryptoProvider {
        cipher_suites,
        kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
        ..base
    })
}

/// Whether `provider` can negotiate nothing but TLS 1.3 with `X25519MLKEM768` (asserted for every configuration built).
#[must_use]
pub fn is_tls13_hybrid_only(provider: &CryptoProvider) -> bool {
    !provider.cipher_suites.is_empty()
        && provider
            .cipher_suites
            .iter()
            .all(|s| s.version() == &rustls::version::TLS13)
        && provider.kx_groups.len() == 1
        && provider.kx_groups.iter().all(|g| g.name() == GROUP)
}

// ---- the SPKI pin ------------------------------------------------------------------------------------------------------

/// One DER element: (tag, the whole element, its content, the bytes after it).
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER element at the start of `input`. Definite lengths only, at most three length bytes, minimal length
/// encoding, single-byte tags; anything else is `None`.
fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, len_bytes) = if first < 0x80 {
        (usize::from(first), 0_usize)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let bytes = after_len.get(..n)?;
        let mut len = 0_usize;
        for b in bytes {
            len = len.checked_mul(256)?.checked_add(usize::from(*b))?;
        }
        // DER: the shortest form (no leading zero byte, long form only from 128 on)
        if bytes.first() == Some(&0) || len < 0x80 {
            return None;
        }
        (len, n)
    };
    let header = len_bytes.checked_add(2)?;
    let total = header.checked_add(len)?;
    let element = input.get(..total)?;
    let content = element.get(header..)?;
    let rest = input.get(total..)?;
    Some((tag, element, content, rest))
}

/// The DER of the `SubjectPublicKeyInfo` of an X.509 certificate (RFC 5280 §4.1: the seventh element of
/// `tbsCertificate` when `version` is present, the sixth otherwise); `None` unless `cert` is exactly one well-formed
/// certificate up to that field.
#[must_use]
pub fn spki_of(cert: &[u8]) -> Option<&[u8]> {
    let (0x30, _, certificate, []) = tlv(cert)? else {
        return None;
    };
    let (0x30, _, tbs, _) = tlv(certificate)? else {
        return None;
    };
    let mut rest = tbs;
    // [0] EXPLICIT version, optional
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.3;
    }
    // serialNumber INTEGER, signature AlgorithmIdentifier, issuer Name, validity, subject Name
    for want in [0x02_u8, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, _, next) = tlv(rest)?;
        if tag != want {
            return None;
        }
        rest = next;
    }
    let (0x30, spki, _, _) = tlv(rest)? else {
        return None;
    };
    Some(spki)
}

/// The pin check of a presented chain (OPEN-M6-09 A): exactly one certificate, whose SPKI hashes to `pin`; compared in
/// constant time.
///
/// # Errors
/// [`Error::Rejected`] otherwise (no detail).
pub fn check_pin(end_entity: &[u8], intermediates: usize, pin: &[u8; HASH_LEN]) -> Result<()> {
    if intermediates != 0 {
        return Err(Error::Rejected);
    }
    let spki = spki_of(end_entity).ok_or(Error::Rejected)?;
    let hash = secmp_crypto::sha256(&[spki]);
    if bool::from(hash.ct_eq(pin)) {
        Ok(())
    } else {
        Err(Error::Rejected)
    }
}

/// The server-certificate verifier of direct mode: the SPKI pin is the only trust anchor; the handshake signatures are
/// verified with the pinned certificate's key (see the module documentation).
#[derive(Debug)]
pub struct PinVerifier {
    pin: [u8; HASH_LEN],
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    /// A verifier for `pin` (`RelayRef.direct.spki_sha256`).
    #[must_use]
    pub fn new(pin: [u8; HASH_LEN]) -> Self {
        Self {
            pin,
            algorithms: crypto_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> core::result::Result<ServerCertVerified, rustls::Error> {
        check_pin(end_entity.as_ref(), intermediates.len(), &self.pin)
            .map(|()| ServerCertVerified::assertion())
            .map_err(|_| {
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            })
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only (the configuration offers no other version)
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> core::result::Result<HandshakeSignatureValid, rustls::Error> {
        // CertificateVerify, checked with the key of the (pinned) certificate (RFC 8446 §4.4.3; TLS-07)
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// ---- the configuration -------------------------------------------------------------------------------------------------

/// The client configuration for a relay pinned by `pin` (see the module documentation).
///
/// # Errors
/// [`Error::Invalid`] if the configuration would offer anything but TLS 1.3 with `X25519MLKEM768` (never in a correct
/// build).
pub fn client_config(pin: [u8; HASH_LEN]) -> Result<Arc<ClientConfig>> {
    let provider = crypto_provider();
    if !is_tls13_hybrid_only(&provider) {
        return Err(Error::Invalid);
    }
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Invalid)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier::new(pin)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    // the `tls12` feature is on in the graph: assert that the configuration as built cannot negotiate it
    if !is_tls13_hybrid_only(config.crypto_provider()) {
        return Err(Error::Invalid);
    }
    Ok(Arc::new(config))
}

// ---- the provider ------------------------------------------------------------------------------------------------------

/// Opens the raw byte stream under TLS: TCP in a shipped build ([`TcpDialer`]), an in-process stream in the tests.
pub trait Dialer: Send + Sync + 'static {
    /// The stream.
    type Stream: ProviderStream;

    /// Open a stream to `host:port`.
    ///
    /// # Errors
    /// [`Error::Closed`] if no connection could be made.
    fn dial(&self, host: &str, port: u16) -> impl Future<Output = Result<Self::Stream>> + Send;
}

/// TCP: the host name is resolved with `tokio::net::lookup_host` (direct mode only, OPEN-M6-26 A), the addresses are
/// tried in order.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    type Stream = tokio::net::TcpStream;

    async fn dial(&self, host: &str, port: u16) -> Result<tokio::net::TcpStream> {
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| Error::Closed)?;
        for addr in addrs {
            if let Ok(stream) = tokio::net::TcpStream::connect(addr).await {
                return Ok(stream);
            }
        }
        Err(Error::Closed)
    }
}

/// The direct-mode provider (see the module documentation).
#[derive(Clone, Debug, Default)]
pub struct TlsProvider<D = TcpDialer> {
    dialer: D,
}

impl TlsProvider<TcpDialer> {
    /// The provider of a shipped build (TCP).
    #[must_use]
    pub const fn new() -> Self {
        Self { dialer: TcpDialer }
    }
}

impl<D> TlsProvider<D> {
    /// A provider over another dialer (the tests).
    pub const fn with_dialer(dialer: D) -> Self {
        Self { dialer }
    }
}

impl<D: Dialer> StreamProvider for TlsProvider<D> {
    type Stream = tokio_rustls::client::TlsStream<D::Stream>;

    async fn connect(&self, relay: &RelayRef, _isolation: Isolation) -> Result<Self::Stream> {
        let direct = relay.direct.as_ref().ok_or(Error::NoDirectEndpoint)?;
        let host = core::str::from_utf8(direct.host.as_bytes()).map_err(|_| Error::Invalid)?;
        let config = client_config(direct.spki_sha256)?;
        let name = ServerName::try_from(host.to_owned()).map_err(|_| Error::Invalid)?;
        let stream = self.dialer.dial(host, direct.port.get()).await?;
        let tls = TlsConnector::from(config)
            .connect(name, stream)
            .await
            .map_err(|_| Error::Rejected)?;
        // ALPN `secmp/1` and the hybrid group, both required before any SecMP byte (TLS-09, TLS-04)
        let (_, session) = tls.get_ref();
        if session.alpn_protocol() != Some(ALPN)
            || session
                .negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name)
                != Some(GROUP)
            || session.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        {
            return Err(Error::Rejected);
        }
        Ok(tls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_is_total_on_short_and_odd_input() {
        assert!(tlv(&[]).is_none());
        assert!(tlv(&[0x30]).is_none());
        assert!(
            tlv(&[0x30, 0x81, 0x10]).is_none(),
            "long form below 128 is not DER"
        );
        assert!(
            tlv(&[0x30, 0x82, 0x00, 0x90]).is_none(),
            "a leading zero length byte is not DER"
        );
        assert!(tlv(&[0x30, 0x80]).is_none(), "indefinite length");
        assert!(tlv(&[0x1f, 0x01, 0x00]).is_none(), "high tag number form");
        assert!(
            tlv(&[0x30, 0x84, 1, 0, 0, 0]).is_none(),
            "more than three length bytes"
        );
        let (tag, whole, content, rest) = tlv(&[0x04, 0x02, 0xaa, 0xbb, 0xcc]).unwrap_or_default();
        assert_eq!(
            (tag, whole, content, rest),
            (
                0x04,
                &[0x04, 0x02, 0xaa, 0xbb][..],
                &[0xaa, 0xbb][..],
                &[0xcc][..]
            )
        );
    }

    #[test]
    fn pin_needs_one_certificate_and_a_parseable_spki() {
        assert_eq!(check_pin(&[], 0, &[0; HASH_LEN]), Err(Error::Rejected));
        assert_eq!(
            check_pin(&[0x30, 0x00], 0, &[0; HASH_LEN]),
            Err(Error::Rejected)
        );
        assert_eq!(
            check_pin(&[0x30, 0x00], 1, &[0; HASH_LEN]),
            Err(Error::Rejected)
        );
    }

    #[test]
    fn the_configuration_is_tls13_with_one_hybrid_group() -> Result<()> {
        let config = client_config([7; HASH_LEN])?;
        assert_eq!(config.crypto_provider().kx_groups.len(), 1);
        assert_eq!(
            config.crypto_provider().kx_groups.first().map(|g| g.name()),
            Some(GROUP)
        );
        assert!(is_tls13_hybrid_only(config.crypto_provider()));
        assert!(!is_tls13_hybrid_only(
            &rustls::crypto::aws_lc_rs::default_provider()
        ));
        assert_eq!(config.alpn_protocols, vec![ALPN.to_vec()]);
        assert!(!config.enable_early_data && !config.enable_sni);
        Ok(())
    }

    /// The length forms at their bounds: short form up to 127, long form from 128 on, `0x80` (BER's indefinite form)
    /// refused even with 128 bytes after it, three length bytes the most (65 536 content bytes pass, a four-byte length
    /// of 16 MiB does not).
    #[test]
    fn tlv_length_forms_at_their_bounds() {
        let short = [&[0x04, 0x7f][..], &[0; 0x7f]].concat();
        assert_eq!(tlv(&short).map(|t| t.2.len()), Some(0x7f));
        let long = [&[0x04, 0x81, 0x80][..], &[0; 0x80]].concat();
        assert_eq!(tlv(&long).map(|t| t.2.len()), Some(0x80));
        let indefinite = [&[0x04, 0x80][..], &[0; 0x80]].concat();
        assert_eq!(tlv(&indefinite), None);
        let three = [&[0x04, 0x83, 0x01, 0x00, 0x00][..], &vec![0; 0x1_0000]].concat();
        assert_eq!(tlv(&three).map(|t| t.2.len()), Some(0x1_0000));
        let four = [
            &[0x04, 0x84, 0x01, 0x00, 0x00, 0x00][..],
            &vec![0; 0x100_0000],
        ]
        .concat();
        assert_eq!(tlv(&four), None);
    }
}
