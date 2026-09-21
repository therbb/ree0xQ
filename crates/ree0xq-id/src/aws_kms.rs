//! AWS KMS backend (SEZ-17, feature `aws-kms`).
//!
//! KMS exposes `ListKeys` + `DescribeKey`; combined they
//! return every CMK in a region with its `KeySpec`, usage,
//! and origin. We map `KeySpec` → `Vec<Primitive>` via
//! [`crate::algos::primitives_for`] so the events look
//! identical to the offline classifier's output.
//!
//! The trait stays narrow so a future GCP KMS / Azure Key
//! Vault impl can drop in without touching the scanner
//! loop. AWS-specific bits live behind the `aws-kms`
//! feature flag so the default build doesn't pull in the
//! aws-sdk-kms crate (compile time matters at the
//! workspace level).

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::algos::primitives_for;
use crate::event::build_event;

/// KMS-agnostic key descriptor. Each backend lists keys
/// once and yields a [`KmsKeyInfo`] per key.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KmsKeyInfo {
    /// Backend-native key identifier. For AWS, this is the
    /// KMS Key ARN.
    pub key_id: String,
    /// Spec string suitable for [`crate::algos::primitives_for`]
    /// (e.g. `RSA`, `ECDSA-P256`, `Ed25519`, `AES`,
    /// `ML-DSA-65`).
    pub key_spec: String,
    /// Bit length for RSA / AES keys; `None` for curve-named
    /// ECC and other specs where the size is implicit.
    pub key_size_bits: Option<u32>,
    /// Free-form usage description (`SIGN_VERIFY`,
    /// `ENCRYPT_DECRYPT`, …).
    pub usage: Option<String>,
    /// `<region>` label so the dashboard can group keys.
    pub region: Option<String>,
}

/// Pluggable cloud-KMS backend.
#[async_trait]
pub trait KmsBackend: Send + Sync {
    /// List every CMK in the configured region; the impl
    /// is responsible for batching / pagination internally.
    async fn list_keys(&self) -> Result<Vec<KmsKeyInfo>>;
    /// Human-readable backend label for log lines.
    fn backend_label(&self) -> &'static str;
}

/// Stats from one [`kms_scan`] pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct KmsScanStats {
    pub keys_seen: usize,
    pub events_emitted: usize,
}

/// Drive a [`KmsBackend`] and emit one
/// `crypto_inventory_event` per discovered key.
pub async fn kms_scan<B, F>(backend: &B, mut on_event: F) -> Result<KmsScanStats>
where
    B: KmsBackend,
    F: FnMut(ree0xq_core::CryptoInventoryEvent),
{
    let keys = backend.list_keys().await?;
    let mut stats = KmsScanStats::default();
    for key in keys {
        stats.keys_seen += 1;
        let prims = primitives_for(&key.key_spec, key.key_size_bits);
        let host = key.region.clone().map(|r| format!("aws-kms:{r}"));
        let rationale = format!(
            "KMS key {} ({}{}{})",
            key.key_id,
            key.key_spec,
            key.key_size_bits
                .map(|b| format!(" {b}b"))
                .unwrap_or_default(),
            key.usage
                .as_deref()
                .map(|u| format!(", usage={u}"))
                .unwrap_or_default(),
        );
        on_event(build_event(key.key_id.clone(), host, prims, rationale));
        stats.events_emitted += 1;
    }
    Ok(stats)
}

/// AWS KMS impl over `aws-sdk-kms`. Walks `ListKeys` +
/// `DescribeKey` for each id; maps `KeySpec` → the spec
/// string the [`crate::algos`] table understands.
///
/// Auth follows the standard AWS SDK chain (env / shared
/// config / IMDS) — ree0xq-id doesn't touch credentials
/// directly.
pub struct AwsKmsBackend {
    client: aws_sdk_kms::Client,
    region: String,
}

impl AwsKmsBackend {
    /// Build a client. `region` selects the KMS endpoint;
    /// when `None`, falls back to the SDK's default
    /// resolution chain.
    pub async fn new(region: Option<&str>) -> Result<Self> {
        let mut loader = aws_config::from_env();
        if let Some(r) = region {
            loader = loader.region(aws_config::Region::new(r.to_string()));
        }
        let cfg = loader.load().await;
        let resolved_region = cfg
            .region()
            .map(|r| r.as_ref().to_string())
            .unwrap_or_else(|| region.unwrap_or("unknown").to_string());
        let client = aws_sdk_kms::Client::new(&cfg);
        Ok(Self {
            client,
            region: resolved_region,
        })
    }
}

#[async_trait]
impl KmsBackend for AwsKmsBackend {
    async fn list_keys(&self) -> Result<Vec<KmsKeyInfo>> {
        let mut out = Vec::new();
        let mut next_marker: Option<String> = None;
        loop {
            let mut req = self.client.list_keys().limit(1000);
            if let Some(m) = next_marker.as_ref() {
                req = req.marker(m.clone());
            }
            let page = req.send().await?;
            for entry in page.keys() {
                let key_id = entry.key_id().unwrap_or_default().to_string();
                let desc = self.client.describe_key().key_id(&key_id).send().await?;
                let meta = match desc.key_metadata() {
                    Some(m) => m,
                    None => continue,
                };
                let key_spec = meta
                    .key_spec()
                    .map(|s| aws_keyspec_to_algo(s.as_str()))
                    .unwrap_or_else(|| "unknown".into());
                let bits = meta.key_spec().and_then(|s| aws_keyspec_bits(s.as_str()));
                out.push(KmsKeyInfo {
                    key_id: meta.arn().unwrap_or(&key_id).to_string(),
                    key_spec,
                    key_size_bits: bits,
                    usage: meta.key_usage().map(|u| u.as_str().to_string()),
                    region: Some(self.region.clone()),
                });
            }
            if page.truncated() {
                next_marker = page.next_marker().map(|s| s.to_string());
                if next_marker.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(out)
    }

    fn backend_label(&self) -> &'static str {
        "aws-kms"
    }
}

/// Map AWS KMS `KeySpec` strings (e.g. `RSA_4096`,
/// `ECC_NIST_P256`) onto the spec names
/// [`crate::algos::primitives_for`] expects.
pub(crate) fn aws_keyspec_to_algo(spec: &str) -> String {
    let upper = spec.to_ascii_uppercase();
    match upper.as_str() {
        "RSA_2048" | "RSA_3072" | "RSA_4096" => "RSA".into(),
        "ECC_NIST_P256" => "ECDSA-P256".into(),
        "ECC_NIST_P384" => "ECDSA-P384".into(),
        "ECC_NIST_P521" => "ECDSA-P521".into(),
        "ECC_SECG_P256K1" => "ECDSA-secp256k1".into(),
        "SYMMETRIC_DEFAULT" => "AES".into(),
        "HMAC_224" => "HMAC-SHA256".into(),
        "HMAC_256" => "HMAC-SHA256".into(),
        "HMAC_384" => "HMAC-SHA384".into(),
        "HMAC_512" => "HMAC-SHA512".into(),
        // ML-DSA when AWS adds it.
        "ML_DSA_44" | "ML-DSA-44" => "ML-DSA-44".into(),
        "ML_DSA_65" | "ML-DSA-65" => "ML-DSA-65".into(),
        "ML_DSA_87" | "ML-DSA-87" => "ML-DSA-87".into(),
        _ => spec.to_string(),
    }
}

/// Bit length for the AWS KMS key specs that encode one.
pub(crate) fn aws_keyspec_bits(spec: &str) -> Option<u32> {
    match spec.to_ascii_uppercase().as_str() {
        "RSA_2048" => Some(2048),
        "RSA_3072" => Some(3072),
        "RSA_4096" => Some(4096),
        "SYMMETRIC_DEFAULT" => Some(256),
        "HMAC_224" => Some(224),
        "HMAC_256" => Some(256),
        "HMAC_384" => Some(384),
        "HMAC_512" => Some(512),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ree0xq_core::PrimitiveRole;

    /// In-memory fake. Used to exercise the scanner loop
    /// + the `KmsKeyInfo → event` mapping without spinning
    /// a real KMS or LocalStack.
    struct FakeKms {
        keys: Vec<KmsKeyInfo>,
    }

    #[async_trait]
    impl KmsBackend for FakeKms {
        async fn list_keys(&self) -> Result<Vec<KmsKeyInfo>> {
            Ok(self.keys.clone())
        }
        fn backend_label(&self) -> &'static str {
            "fake-kms"
        }
    }

    #[tokio::test]
    async fn maps_each_keyspec_to_the_right_primitive() {
        let fake = FakeKms {
            keys: vec![
                KmsKeyInfo {
                    key_id: "arn:aws:kms:us-east-1::key/rsa".into(),
                    key_spec: "RSA".into(),
                    key_size_bits: Some(4096),
                    usage: Some("SIGN_VERIFY".into()),
                    region: Some("us-east-1".into()),
                },
                KmsKeyInfo {
                    key_id: "arn:aws:kms:us-east-1::key/ecc".into(),
                    key_spec: "ECDSA-P256".into(),
                    key_size_bits: None,
                    usage: Some("SIGN_VERIFY".into()),
                    region: Some("us-east-1".into()),
                },
                KmsKeyInfo {
                    key_id: "arn:aws:kms:us-east-1::key/sym".into(),
                    key_spec: "AES".into(),
                    key_size_bits: Some(256),
                    usage: Some("ENCRYPT_DECRYPT".into()),
                    region: Some("us-east-1".into()),
                },
                KmsKeyInfo {
                    key_id: "arn:aws:kms:us-east-1::key/pq".into(),
                    key_spec: "ML-DSA-65".into(),
                    key_size_bits: None,
                    usage: Some("SIGN_VERIFY".into()),
                    region: Some("us-east-1".into()),
                },
            ],
        };
        let mut events = Vec::new();
        let stats = kms_scan(&fake, |ev| events.push(ev)).await.unwrap();
        assert_eq!(stats.keys_seen, 4);
        assert_eq!(stats.events_emitted, 4);

        // Find each by identity and check primitives.
        let rsa = events
            .iter()
            .find(|e| e.asset.identity.contains("rsa"))
            .unwrap();
        assert!(rsa
            .primitives
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm.starts_with("RSA-PKCS1")));
        let pq = events
            .iter()
            .find(|e| e.asset.identity.contains("pq"))
            .unwrap();
        assert!(pq
            .primitives
            .iter()
            .any(|p| p.role == PrimitiveRole::Sig && p.algorithm == "ML-DSA-65"));
        assert_eq!(pq.primitives[0].pq_resistant, Some(true));

        // Host carries the AWS region for dashboard grouping.
        for ev in &events {
            assert_eq!(ev.asset.host.as_deref(), Some("aws-kms:us-east-1"));
        }
    }

    #[test]
    fn aws_keyspec_mapping_is_complete() {
        assert_eq!(aws_keyspec_to_algo("RSA_4096"), "RSA");
        assert_eq!(aws_keyspec_to_algo("ECC_NIST_P256"), "ECDSA-P256");
        assert_eq!(aws_keyspec_to_algo("ECC_SECG_P256K1"), "ECDSA-secp256k1");
        assert_eq!(aws_keyspec_to_algo("SYMMETRIC_DEFAULT"), "AES");
        assert_eq!(aws_keyspec_to_algo("HMAC_384"), "HMAC-SHA384");
        // Unknown passes through.
        assert_eq!(aws_keyspec_to_algo("FUTURE_SPEC"), "FUTURE_SPEC");

        assert_eq!(aws_keyspec_bits("RSA_4096"), Some(4096));
        assert_eq!(aws_keyspec_bits("ECC_NIST_P256"), None);
        assert_eq!(aws_keyspec_bits("SYMMETRIC_DEFAULT"), Some(256));
    }
}
