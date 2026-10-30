use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use anyhow::anyhow;

pub trait HmacSha256SignerTrait {
    fn new(secret: impl Into<String>) -> Self;

    fn sign(&self, timestamp: i64, body: &[u8]) -> Result<String, anyhow::Error>;

    fn verify(
        &self,
        timestamp: i64,
        body: &[u8],
        signature: &str,
        tolerance: Option<i64>,
    ) -> Result<bool, anyhow::Error>;
}

pub type HmacSha256 = Hmac<Sha256>;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct HmacSha256Signer(String);

impl HmacSha256SignerTrait for HmacSha256Signer {
    fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    fn sign(&self, timestamp: i64, body: &[u8]) -> Result<String, anyhow::Error> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_bytes())?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);

        let signature = hex::encode(mac.clone().finalize().into_bytes());
        Ok(signature)
    }

    fn verify(
        &self,
        timestamp: i64,
        body: &[u8],
        signature: &str,
        tolerance: Option<i64>,
    ) -> Result<bool, anyhow::Error> {
        // 接收端需要检查时间窗口
        // 1. 时间窗口检查（可选）
        if let Some(tolerance) = tolerance {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

            if tolerance < 0 || (now - timestamp).abs() > tolerance {
                return Err(anyhow!(
                    "signature verify failed, timestamp is out of time window"
                ));
            }
        }

        // 2. 计算签名
        let mut mac = HmacSha256::new_from_slice(self.0.as_bytes())?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);

        let received_bytes = match hex::decode(signature) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(anyhow!("signature decode error: {}", e));
            }
        };

        match mac.verify_slice(&received_bytes[..]) {
            Ok(_) => Ok(true),
            Err(err) => Err(anyhow!("signature verify error: {}", err)),
        }
    }
}

#[cfg(feature = "wasm")]
impl HmacSha256Signer {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    pub fn sign(&self, timestamp: i64, body: &[u8]) -> Result<String, JsValue> {
        HmacSha256SignerTrait::sign(self, timestamp, body)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    pub fn verify(
        &self,
        timestamp: i64,
        body: &[u8],
        signature: &str,
        tolerance: Option<i64>,
    ) -> Result<bool, JsValue> {
        HmacSha256SignerTrait::verify(self, timestamp, body, signature, tolerance)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{HmacSha256Signer, HmacSha256SignerTrait};

    #[test]
    fn test_signer() {
        let signer = HmacSha256Signer::new("abcd");

        let payload = serde_json::json!({
            "a": "b",
            "c": 3
        })
        .to_string();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        println!("now: {}", now);

        let sig = signer.sign(now, payload.as_bytes()).unwrap();
        println!("sig: {}", sig);
    }

    #[test]
    fn test_signer_valid() {
        let signer = HmacSha256Signer::new("abcd");

        let payload = serde_json::json!({
            "a": "b",
            "c": 3
        })
        .to_string();

        let now = 1793352268_i64;
        let sig = "34fc2fb4d1abc2e9e8456657ca0e743affcae84e604978784407c52fc48b1543".to_string();

        let valid = match signer.verify(now, payload.as_bytes(), &sig, None) {
            Ok(valid) => valid,
            Err(e) => {
                println!("error: {}", e);
                false
            }
        };

        assert!(valid);
    }
}
