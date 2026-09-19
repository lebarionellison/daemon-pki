use std::net::IpAddr;

use daemon_pki_core::{
    ca::{IntermediateCa, RootCa},
    certificate::{CertificateIssuer, CertificateRequest},
    validation::{
        CertificateValidationInput,
        CertificateValidity,
        ChainValidator,
        IdentityRequirement,
        TrustAnchor,
        TrustStore,
    },
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Daemon PKI cryptographic chain verification");
    println!();

    // ------------------------------------------------------------
    // Generate the complete CA hierarchy.
    // ------------------------------------------------------------
    let root = RootCa::generate("Daemon PKI Root CA")?;
    println!("Root CA: generated");

    let intermediate =
        IntermediateCa::generate(&root, "Daemon PKI Workload CA")?;
    println!("Intermediate CA: generated");

    // ------------------------------------------------------------
    // Issue a leaf certificate.
    // ------------------------------------------------------------
    let request = CertificateRequest::new("api.daemon.internal")
        .with_dns_name("api.daemon.internal")
        .with_dns_name("api.internal")
        .with_ip_address("127.0.0.1".parse::<IpAddr>()?);

    let (certificate, private_key) =
        CertificateIssuer::issue(&intermediate, request)?;

    println!("Leaf certificate: issued");
    println!("Leaf DER bytes: {}", certificate.der().len());
    println!(
        "Leaf private key DER bytes: {}",
        private_key.serialize_der().len()
    );

    // ------------------------------------------------------------
    // Register the actual Root CA as a trust anchor.
    // ------------------------------------------------------------
    let trust_anchor = TrustAnchor::new(
        "Daemon PKI Root CA",
        root.certificate_der().to_vec(),
    );

    let mut trust_store = TrustStore::new();
    let trust_anchor_id = trust_store.add(trust_anchor)?;

    println!("Trust anchor: {}", trust_anchor_id);

    // ------------------------------------------------------------
    // Perform actual cryptographic chain verification.
    // ------------------------------------------------------------
    let result = ChainValidator::validate_der_chain(
        certificate.der(),
        &intermediate.certificate_der(), 
        &root.certificate_der(), 
        &trust_store,
    )?;

    println!();
    println!("Cryptographic chain verification:");
    println!("  Trusted     : {}", result.trusted);
    println!("  Chain depth: {}", result.chain_depth);

    match result.trust_anchor_id {
        Some(id) => println!("  Trust anchor: {}", id),
        None => println!("  Trust anchor: none"),
    }

    if !result.trusted {
        return Err(
            "cryptographic certificate chain validation failed".into()
        );
    }

    println!();
    println!("Root -> Intermediate signature: VERIFIED");
    println!("Intermediate -> Leaf signature: VERIFIED");
    println!("Root self-signature: VERIFIED");
    println!("CA constraints: VERIFIED");
    println!("Validity windows: VERIFIED");
    println!("Leaf key usage: VERIFIED");
    println!("Explicit trust anchor: VERIFIED");

    // ------------------------------------------------------------
    // Also demonstrate the existing identity/policy validator.
    // ------------------------------------------------------------
    let (_, parsed) =
        x509_parser::parse_x509_certificate(certificate.der())?;

    let validity = parsed.validity();

    let mut dns_names = Vec::new();
    let mut ip_addresses = Vec::new();
    let mut digital_signature = false;
    let mut key_cert_sign = false;
    let mut server_auth = false;
    let mut client_auth = false;

    for extension in parsed.extensions() {
        match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::KeyUsage(usage) => {
                digital_signature = usage.digital_signature();
                key_cert_sign = usage.key_cert_sign();
            }

            x509_parser::extensions::ParsedExtension::ExtendedKeyUsage(eku) => {
                server_auth = eku.server_auth;
                client_auth = eku.client_auth;
            }

            x509_parser::extensions::ParsedExtension::SubjectAlternativeName(
                san,
            ) => {
                for name in &san.general_names {
                    match name {
                        x509_parser::extensions::GeneralName::DNSName(name) => {
                            dns_names.push((*name).to_string());
                        }

                        x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                            if bytes.len() == 4 {
                                ip_addresses.push(IpAddr::from([
                                    bytes[0],
                                    bytes[1],
                                    bytes[2],
                                    bytes[3],
                                ]));
                            } else if bytes.len() == 16 {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(bytes);
                                ip_addresses.push(IpAddr::from(octets));
                            }
                        }

                        _ => {}
                    }
                }
            }

            _ => {}
        }
    }

    let validation_input = CertificateValidationInput {
        der: certificate.der().to_vec(),

        validity: CertificateValidity {
            not_before: validity.not_before.to_datetime(),
            not_after: validity.not_after.to_datetime(),
        },

        is_ca: parsed.is_ca(),

        digital_signature,
        key_cert_sign,

        server_auth,
        client_auth,

        dns_names,
        ip_addresses,

        issuer: parsed.issuer().to_string(),
        subject: parsed.subject().to_string(),
    };

    let identity =
        IdentityRequirement::dns("api.daemon.internal");

    ChainValidator::validate_leaf(
        &validation_input,
        &trust_store,
        Some(&identity),
    )?;

    println!("Workload identity policy: VERIFIED");

    println!();
    println!("==================================================");
    println!("Daemon PKI cryptographic verification: PASSED");
    println!("==================================================");
    println!();

    println!("Private keys remained in memory only.");

    Ok(())
}

