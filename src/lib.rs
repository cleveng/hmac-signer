use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use anyhow::anyhow;

pub trait HmacSha256SignerTrait {
    fn new(secret: impl Into<String>) -> Self;

    fn current_timestamp() -> i64;

    fn sign<T: Serialize + ?Sized>(
        &self,
        body: &T,
        timestamp: Option<i64>,
    ) -> Result<(i64, String), anyhow::Error>;

    fn verify<T: Serialize + ?Sized>(
        &self,
        body: &T,
        timestamp: i64,
        signature: &str,
        tolerance: Option<i64>,
    ) -> Result<bool, anyhow::Error>;
}

pub type HmacSha256 = Hmac<Sha256>;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct HmacSha256Signer(String);

impl HmacSha256Signer {
    fn build_sign_body<T: Serialize + ?Sized>(input: &T) -> Result<Vec<u8>, anyhow::Error> {
        let mut value = serde_json::to_value(input)?;

        if let serde_json::Value::Object(ref mut map) = value {
            map.remove("timestamp");
            map.remove("sign");
        }

        let sorted: BTreeMap<String, serde_json::Value> = serde_json::from_value(value)?;
        Ok(serde_json::to_vec(&sorted)?)
    }

    fn calculate(&self, timestamp: i64, body: &[u8]) -> Result<String, anyhow::Error> {
        let mut mac = HmacSha256::new_from_slice(self.0.as_bytes())?;

        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);

        Ok(hex::encode(mac.finalize().into_bytes()))
    }
}

impl HmacSha256SignerTrait for HmacSha256Signer {
    fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System clock is before Unix epoch")
            .as_secs() as i64
    }

    fn sign<T: Serialize + ?Sized>(
        &self,
        body: &T,
        timestamp: Option<i64>,
    ) -> Result<(i64, String), anyhow::Error> {
        let timestamp = timestamp.unwrap_or_else(|| Self::current_timestamp());

        let payload = Self::build_sign_body(body)?;
        let signature = self.calculate(timestamp, &payload)?;

        Ok((timestamp, signature))
    }

    fn verify<T: Serialize + ?Sized>(
        &self,
        body: &T,
        timestamp: i64,
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
        let payload = Self::build_sign_body(body)?;
        let expected = self.calculate(timestamp, &payload)?;

        let received_bytes = hex::decode(signature)
            .map_err(|_| anyhow!("invalid signature format: expected hexadecimal"))?;

        let expected_bytes = hex::decode(expected)?;

        if received_bytes.len() != expected_bytes.len() {
            return Err(anyhow!("signature verification failed: signature mismatch"));
        }

        if expected_bytes.ct_eq(&received_bytes).into() {
            Ok(true)
        } else {
            Err(anyhow!("signature verification failed: signature mismatch"))
        }
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl HmacSha256Signer {
    #[wasm_bindgen(constructor)]
    pub fn new(secret: String) -> HmacSha256Signer {
        HmacSha256Signer(secret)
    }

    pub fn sign(&self, body: &[u8], timestamp: Option<i64>) -> Result<JsValue, JsValue> {
        let (timestamp, signature) = HmacSha256SignerTrait::sign(self, &body, timestamp)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let result = js_sys::Object::new();

        js_sys::Reflect::set(
            &result,
            &"timestamp".into(),
            &JsValue::from_f64(timestamp as f64),
        )?;

        js_sys::Reflect::set(&result, &"signature".into(), &JsValue::from_str(&signature))?;

        Ok(result.into())
    }

    pub fn verify(
        &self,
        body: &[u8],
        timestamp: i64,
        signature: &str,
        tolerance: Option<i64>,
    ) -> Result<bool, JsValue> {
        HmacSha256SignerTrait::verify(self, body, timestamp, signature, tolerance)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{HmacSha256Signer, HmacSha256SignerTrait};

    #[test]
    fn test_signer() {
        let signer = HmacSha256Signer::new("abcd");

        let payload = serde_json::json!({
            "a": "b",
            "c": 3
        });

        let sig = signer.sign(&payload, None).unwrap();
        println!("sig: {:#?}", sig);
    }

    #[test]
    fn test_signer_valid() {
        let signer = HmacSha256Signer::new("abcd");

        let payload = serde_json::json!({
            "a": "b",
            "c": 3
        });

        let now = 1793599063_i64;
        let sig = "88587a0a4305464c37938709dcc03c6cbff57fc86e3d384dee64a0a39b08d330".to_string();

        let valid = match signer.verify(&payload, now, &sig, None) {
            Ok(valid) => valid,
            Err(e) => {
                println!("error: {}", e);
                false
            }
        };

        assert!(valid);
    }
}
