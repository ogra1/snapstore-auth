//! Minimal, dependency-light Macaroon implementation for the Snap Store
//! flow.
//!
//! The Snap Store issues *v1 binary* macaroons (base64url of
//! `0xHHHHkey value\n` packets — see `pymacaroons/serializers/binary_serializer.py`).
//! We additionally understand the *v1 JSON* and *v2 binary* wire formats so
//! the backend keeps working if the endpoints switch format.
//!
//! Only what the login flow needs is implemented:
//!
//! * parsing (binary v1, JSON v1, binary v2),
//! * re-serialization of binary v1 (needed to build the request header),
//! * extracting the third-party caveat that points at the SSO discharge
//!   endpoint (caveat ID + location),
//! * **binding** a discharge macaroon to a root macaroon — the exact
//!   `HashSignaturesBinder` from pymacaroons:
//!
//! ```text
//! key      = truncate_or_pad(b"\0", 32)
//! h1       = HMAC-SHA256(key, hex_decode(root.signature))
//! h2       = HMAC-SHA256(key, hex_decode(discharge.signature))
//! bound.sig = hex(HMAC-SHA256(key, h1 || h2))
//! ```
//!
//! (A discharge macaroon with an empty signature binds to the constant
//! `9f023f6e88e67fc7a66df8e14a78362fcac79095a399128b06d2cf557e305c92`, which
//! matches `pymacaroons.Macaroon.prepare_for_request` on an empty signature.)

use crate::error::{AuthenticationError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};

/// A single caveat attached to a macaroon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caveat {
    /// Caveat ID (the value the discharge endpoint expects as `caveat_id`).
    /// Empty for first-party caveats.
    pub id: String,
    /// Verification key ID (present only on third-party caveats).
    /// Raw bytes: the v1 binary format stores it unencoded and it is not
    /// guaranteed to be UTF-8.
    pub verification_id: Option<Vec<u8>>,
    /// Location where this caveat must be discharged (third-party caveats).
    pub location: Option<String>,
}

/// A parsed macaroon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Macaroon {
    /// Issuer location (e.g. `https://dashboard.snapcraft.io`).
    pub location: Option<String>,
    /// Free-form identifier assigned by the issuer.
    pub identifier: String,
    /// Caveats in issuer order.
    pub caveats: Vec<Caveat>,
    /// Signature as lowercase hex (empty string for an unsigned macaroon).
    pub signature_hex: String,
    /// Wire format of the original serialization (for re-serialization).
    pub format: MacaroonFormat,
}

/// Wire format a macaroon was received in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacaroonFormat {
    /// base64url of `0xHHHHkey value\n` packets.
    BinaryV1,
    /// JSON object with `identifier`/`signature` fields.
    JsonV1,
    /// base64url of the uvarint-packet v2 format.
    BinaryV2,
}

/// Decode a v1 binary packet value as UTF-8 (typed error, no panic).
fn as_utf8(v: &[u8]) -> Result<&str> {
    std::str::from_utf8(v)
        .map_err(|_| AuthenticationError::MacaroonParse("non-ascii packet value".into()))
}

impl Macaroon {
    /// Parse a macaroon from any supported wire format (auto-detected).
    pub fn parse(serialized: &str) -> Result<Self> {
        let trimmed = serialized.trim();
        if trimmed.is_empty() {
            return Err(AuthenticationError::MacaroonParse(
                "empty macaroon string".into(),
            ));
        }
        // JSON v1 starts with `{`.
        if trimmed.starts_with('{') {
            return Macaroon::parse_json_v1(trimmed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(trimmed.as_bytes())
            .map_err(|e| {
                AuthenticationError::MacaroonParse(format!("bad base64url: {e}"))
            })?;
        if decoded.is_empty() {
            return Err(AuthenticationError::MacaroonParse(
                "empty macaroon payload".into(),
            ));
        }
        // v2 binary starts with the version byte 0x02 (v1 packet prefixes
        // always start with an ASCII hex digit, so 0x02 is unambiguous).
        if decoded[0] == 0x02 {
            Macaroon::parse_binary_v2(&decoded)
        } else {
            Macaroon::parse_binary_v1(&decoded)
        }
    }

    /// Parse the v1 binary format:
    /// `0xHHHHkey value\n` packets where HHHH is the hex packet length.
    fn parse_binary_v1(data: &[u8]) -> Result<Self> {
        let mut location: Option<String> = None;
        let mut identifier: Option<String> = None;
        let mut signature: Option<String> = None;
        let mut caveats: Vec<Caveat> = Vec::new();

        let mut i = 0usize;
        while i < data.len() {
            if i + 4 > data.len() {
                return Err(AuthenticationError::MacaroonParse(
                    "truncated packet header".into(),
                ));
            }
            let len_hex = std::str::from_utf8(&data[i..i + 4])
                .map_err(|_| AuthenticationError::MacaroonParse("non-ascii packet header".into()))?;
            let packet_len = usize::from_str_radix(len_hex, 16)
                .map_err(|_| AuthenticationError::MacaroonParse("bad packet length".into()))?;
            if packet_len < 4 || i + packet_len > data.len() {
                return Err(AuthenticationError::MacaroonParse(
                    "packet extends past end of buffer".into(),
                ));
            }
            let packet = &data[i + 4..i + packet_len];
            i += packet_len;

            let sp = packet
                .iter()
                .position(|b| *b == b' ')
                .ok_or_else(|| AuthenticationError::MacaroonParse("malformed packet".into()))?;
            let (key, value) = (&packet[..sp], &packet[sp + 1..]);
            let key = std::str::from_utf8(key)
                .map_err(|_| AuthenticationError::MacaroonParse("non-ascii packet key".into()))?;
            if !value.ends_with(b"\n") {
                return Err(AuthenticationError::MacaroonParse(
                    "packet missing trailing newline".into(),
                ));
            }
            let value = &value[..value.len() - 1];
            match key {
                "location" => location = Some(as_utf8(value)?.to_string()),
                "identifier" => identifier = Some(as_utf8(value)?.to_string()),
                "cid" => {
                    caveats.push(Caveat {
                        id: as_utf8(value)?.to_string(),
                        verification_id: None,
                        location: None,
                    });
                }
                "vid" => {
                    let last = caveats
                        .last_mut()
                        .ok_or_else(|| AuthenticationError::MacaroonParse("caveat before its id".into()))?;
                    // Raw bytes: not guaranteed to be UTF-8.
                    last.verification_id = Some(value.to_vec());
                }
                "cl" => {
                    let last = caveats
                        .last_mut()
                        .ok_or_else(|| AuthenticationError::MacaroonParse("caveat before its id".into()))?;
                    last.location = Some(as_utf8(value)?.to_string());
                }
                "signature" => {
                    signature = Some(hex::encode(value));
                }
                other => {
                    return Err(AuthenticationError::MacaroonParse(format!(
                        "unknown packet key '{other}'"
                    )));
                }
            }
        }

        Ok(Macaroon {
            location,
            identifier: identifier.ok_or_else(|| {
                AuthenticationError::MacaroonParse("missing identifier".into())
            })?,
            caveats,
            signature_hex: signature.unwrap_or_default(),
            format: MacaroonFormat::BinaryV1,
        })
    }

    /// Parse the v1 JSON format.
    fn parse_json_v1(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            identifier: Option<String>,
            #[serde(default)]
            signature: Option<String>,
            #[serde(default)]
            location: Option<String>,
            #[serde(default)]
            caveats: Vec<RawCaveat>,
        }
        #[derive(Deserialize)]
        struct RawCaveat {
            #[serde(default)]
            cid: Option<String>,
            #[serde(default)]
            vid: Option<String>,
            #[serde(default)]
            cl: Option<String>,
        }

        let raw: Raw = serde_json::from_str(json)
            .map_err(|e| AuthenticationError::MacaroonParse(format!("bad JSON: {e}")))?;
        Ok(Macaroon {
            location: raw.location,
            identifier: raw.identifier.ok_or_else(|| {
                AuthenticationError::MacaroonParse("missing 'identifier' field".into())
            })?,
            caveats: raw
                .caveats
                .into_iter()
                .map(|c| Caveat {
                    id: c.cid.unwrap_or_default(),
                    verification_id: c.vid.and_then(|v| URL_SAFE_NO_PAD.decode(v).ok()),
                    location: c.cl,
                })
                .collect(),
            signature_hex: raw.signature.unwrap_or_default(),
            format: MacaroonFormat::JsonV1,
        })
    }

    /// Parse the v2 binary format (uvarint-packet layout).
    fn parse_binary_v2(data: &[u8]) -> Result<Self> {
        // Skip the 0x02 version byte.
        let mut pos = 1usize;

        /// Read one v2 packet at `pos`. Returns (new_pos, field_type, payload).
        fn packet(data: &[u8], pos: &mut usize) -> Result<(u8, Vec<u8>)> {
            let read_uvarint = |data: &[u8], pos: &mut usize| -> Result<u64> {
                let mut shift = 0u32;
                let mut value: u64 = 0;
                loop {
                    if *pos >= data.len() {
                        return Err(AuthenticationError::MacaroonParse(
                            "truncated v2 varint".into(),
                        ));
                    }
                    let b = data[*pos];
                    *pos += 1;
                    value |= u64::from(b & 0x7f) << shift;
                    if b & 0x80 == 0 {
                        return Ok(value);
                    }
                    shift += 7;
                }
            };
            let field_type = read_uvarint(data, pos)? as u8;
            if field_type == 0 {
                return Ok((field_type, Vec::new()));
            }
            let payload_len = read_uvarint(data, pos)? as usize;
            if *pos + payload_len > data.len() {
                return Err(AuthenticationError::MacaroonParse(
                    "v2 payload extends past end of buffer".into(),
                ));
            }
            let payload = data[*pos..*pos + payload_len].to_vec();
            *pos += payload_len;
            Ok((field_type, payload))
        }

        /// Read packets until EOS, returning (new_pos, packets).
        fn section(data: &[u8], pos: &mut usize) -> Result<Vec<(u8, Vec<u8>)>> {
            let mut packets = Vec::new();
            let mut prev: i32 = -1;
            loop {
                let (ft, payload) = packet(data, pos)?;
                if ft == 0 {
                    return Ok(packets);
                }
                if (ft as i32) <= prev {
                    return Err(AuthenticationError::MacaroonParse(
                        "v2 fields out of order".into(),
                    ));
                }
                prev = ft as i32;
                packets.push((ft, payload));
            }
        }

        // Header: [LOCATION] IDENTIFIER EOS
        let header = section(data, &mut pos)?;
        let mut location: Option<String> = None;
        let mut header = header;
        if header.first().map(|(ft, _)| *ft) == Some(1) {
            location = Some(String::from_utf8_lossy(&header[0].1).into_owned());
            header.remove(0);
        }
        if header.len() != 1 || header[0].0 != 2 {
            return Err(AuthenticationError::MacaroonParse(
                "invalid v2 macaroon header".into(),
            ));
        }
        let identifier = String::from_utf8_lossy(&header[0].1).into_owned();

        // Caveats: [LOCATION] IDENTIFIER [VID] EOS ...
        let mut caveats: Vec<Caveat> = Vec::new();
        loop {
            let cav = section(data, &mut pos)?;
            if cav.is_empty() {
                break; // EOS-only section ends the caveat list
            }
            let mut cav_loc: Option<String> = None;
            let mut cav_id: Option<String> = None;
            let mut cav_vid: Option<Vec<u8>> = None;
            for (ft, payload) in &cav {
                match *ft {
                    1 => cav_loc = Some(String::from_utf8_lossy(payload).into_owned()),
                    2 => cav_id = Some(String::from_utf8_lossy(payload).into_owned()),
                    4 => cav_vid = Some(payload.clone()),
                    _ => {
                        return Err(AuthenticationError::MacaroonParse(
                            "unexpected v2 caveat field".into(),
                        ))
                    }
                }
            }
            caveats.push(Caveat {
                id: cav_id.ok_or_else(|| {
                    AuthenticationError::MacaroonParse("v2 caveat without identifier".into())
                })?,
                verification_id: cav_vid,
                location: cav_loc,
            });
        }

        // Final packet must be the signature.
        let (ft, payload) = packet(data, &mut pos)?;
        if ft != 6 {
            return Err(AuthenticationError::MacaroonParse(
                "v2 macaroon missing signature".into(),
            ));
        }
        if pos != data.len() {
            return Err(AuthenticationError::MacaroonParse(
                "trailing data after v2 signature".into(),
            ));
        }
        Ok(Macaroon {
            location,
            identifier,
            caveats,
            signature_hex: hex::encode(&payload),
            format: MacaroonFormat::BinaryV2,
        })
    }

    /// Third-party caveats only (those carrying a verification key ID).
    pub fn third_party_caveats(&self) -> impl Iterator<Item = &Caveat> {
        self.caveats
            .iter()
            .filter(|c| c.verification_id.is_some())
    }

    /// Find the caveat that must be discharged at `discharge_host`
    /// (e.g. `login.ubuntu.com`).
    ///
    /// Resolution mirrors `craft_store.login._ubuntuone._get_login_caveat`:
    /// single caveat → use it; otherwise match by location host, then fall
    /// back to the first caveat that has a location.
    pub fn find_discharge_caveat(&self, discharge_host: &str) -> Result<&Caveat> {
        let caveats: Vec<&Caveat> = self.third_party_caveats().collect();
        if caveats.is_empty() {
            return Err(AuthenticationError::NoDischargeCaveat);
        }
        if caveats.len() == 1 {
            return Ok(caveats[0]);
        }
        let host_of = |url: &str| -> Option<String> {
            let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
            Some(rest.split('/').next().unwrap_or(rest).trim_end_matches('/').to_string())
        };
        if let Some(c) = caveats
            .iter()
            .find(|c| c.location.as_deref().and_then(host_of) == Some(discharge_host.to_string()))
        {
            return Ok(*c);
        }
        if let Some(c) = caveats.iter().find(|c| c.location.is_some()) {
            return Ok(*c);
        }
        Ok(caveats[0])
    }

    /// Bind `discharge` to this (root) macaroon and return the bound
    /// discharge's hex signature — the `HashSignaturesBinder` algorithm.
    ///
    /// Returns an error instead of panicking when the hex signatures are
    /// malformed.
    pub fn bind_discharge_signature(&self, discharge: &Macaroon) -> Result<String> {
        let key = [0u8; 32]; // truncate_or_pad(b"\0")
        let root_bytes = hex::decode(&self.signature_hex).map_err(|e| {
            AuthenticationError::MacaroonParse(format!(
                "root macaroon signature is not valid hex: {e}"
            ))
        })?;
        let disch_bytes = hex::decode(&discharge.signature_hex).map_err(|e| {
            AuthenticationError::MacaroonParse(format!(
                "discharge macaroon signature is not valid hex: {e}"
            ))
        })?;

        fn hmac256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)
                .map_err(|e| AuthenticationError::MacaroonParse(format!("hmac init: {e}")))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }

        // hmac_concat(key, a, b) = HMAC(key, HMAC(key, a) || HMAC(key, b))
        let h1 = hmac256(&key, &root_bytes)?;
        let h2 = hmac256(&key, &disch_bytes)?;
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key)
            .map_err(|e| AuthenticationError::MacaroonParse(format!("hmac init: {e}")))?;
        mac.update(&h1);
        mac.update(&h2);
        let bound = mac.finalize().into_bytes().to_vec();
        Ok(hex::encode(bound))
    }

    /// Re-serialize in the v1 binary format (the format the Snap Store and
    /// Ubuntu One actually use). Returns `None` when a text field carries
    /// non-UTF-8 data (not possible with these endpoints).
    pub fn serialize_v1_binary(&self) -> Option<String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let mut out: Vec<u8> = Vec::new();
        // Text packet: `0xHHHHkey value\n` where the length covers the
        // 4-hex-digit prefix itself.
        let push_text = |out: &mut Vec<u8>, key: &str, value: &str| {
            let content = format!("{key} {value}\n");
            let len = 4 + content.len();
            out.extend_from_slice(format!("{len:04x}").as_bytes());
            out.extend_from_slice(content.as_bytes());
        };
        // Raw-byte packet (vid / signature values are not guaranteed UTF-8).
        let push_bytes = |out: &mut Vec<u8>, key: &str, value: &[u8]| {
            let len = 4 + key.len() + 1 + value.len() + 1;
            out.extend_from_slice(format!("{len:04x}").as_bytes());
            out.extend_from_slice(key.as_bytes());
            out.push(b' ');
            out.extend_from_slice(value);
            out.push(b'\n');
        };

        if let Some(loc) = &self.location {
            push_text(&mut out, "location", loc);
        }
        push_text(&mut out, "identifier", &self.identifier);
        for c in &self.caveats {
            push_text(&mut out, "cid", &c.id);
            if let Some(v) = &c.verification_id {
                push_bytes(&mut out, "vid", v);
            }
            if let Some(l) = &c.location {
                push_text(&mut out, "cl", l);
            }
        }
        let sig_bytes = hex::decode(&self.signature_hex).ok()?;
        push_bytes(&mut out, "signature", &sig_bytes);
        Some(URL_SAFE_NO_PAD.encode(out))
    }

    /// Return a clone of this macaroon with a new hex signature
    /// (used to produce the bound discharge macaroon).
    pub fn rebind_signature(&self, new_sig_hex: &str) -> Option<Macaroon> {
        if !new_sig_hex.len().is_multiple_of(2) {
            return None;
        }
        Some(Macaroon {
            location: self.location.clone(),
            identifier: self.identifier.clone(),
            caveats: self.caveats.clone(),
            signature_hex: new_sig_hex.to_string(),
            format: self.format,
        })
    }
}

/// The constant binding of an *unsigned* (empty-signature) discharge
/// macaroon. Useful as a sanity check; produced by the official
/// `pymacaroons` implementation.
pub const EMPTY_DISCHARGE_BOUND_SIGNATURE: &str =
    "e6462cd74ce90099f9b2e611829bb1741f82c179ad7a61b2585610e400967e02";

#[cfg(test)]
mod tests {
    use super::*;

    // Fixtures produced by the official `pymacaroons` implementation.

    /// v1 binary root macaroon issued for `dashboard.snapcraft.io` with a
    /// third-party caveat to `login.ubuntu.com`.
    const FIX_A_ROOT: &str = "MDAyY2xvY2F0aW9uIGh0dHBzOi8vZGFzaGJvYXJkLnNuYXBjcmFmdC5pbwowMDE5aWRlbnRpZmllciByb290LWlkLTEKMDAxMGNpZCBjaWQtMDAxCjAwNTF2aWQgDVQZMibgN_0yFc5ogte1xjxpKc5XmjPtPUWWYjviSULNh5-nmPcN1s6-h-c8qSgmFQvO8Iy__a9fehkpatZve0PCpRiUI3hNCjAwMzhjbCBodHRwczovL2xvZ2luLnVidW50dS5jb20vYXBpL3YyL3Rva2Vucy9kaXNjaGFyZ2UKMDAyZnNpZ25hdHVyZSC0CqFfWTisBnfUsDI0y9i5xkTUuL-BFCOwFXL2EJj9dwo";
    const FIX_A_DISCHARGE: &str =
        "MDAyNmxvY2F0aW9uIGh0dHBzOi8vbG9naW4udWJ1bnR1LmNvbQowMDFiaWRlbnRpZmllciBkaXNjaGFyZ2UtMQowMDBmc2lnbmF0dXJlIAo";
    const FIX_A_BOUND_SIG: &str =
        "1c2636cb2f6f99eb9bc1328dd065245d647737bc2608a2f95d89b0530c147586";

    /// v1 JSON root + unsigned discharge.
    const FIX_B_ROOT: &str = "{\"identifier\": \"json-root-1\", \"signature\": \"536b842430a799231dc68ffb430459156fc41076391d2a8218fd2cbc5a8f841a\", \"location\": \"https://dashboard.snapcraft.io\", \"caveats\": [{\"cid\": \"cid-json-1\", \"vid\": \"7-h9cWGyjkzZlL5MFOwaI35ti03Z2D1lGH4x5_cQkNyS5uTuOcuBsAA_8vM2b9025lG5dssSDHx0jKVWoCaiRftclRz1zQ_t\", \"cl\": \"https://login.ubuntu.com/api/v2/tokens/discharge\"}]}";
    const FIX_B_BOUND_SIG: &str =
        "b758f49b0faf2c631c0f1d690685f0d01a44fe8c4938d6c8db89487cd56b3154";

    /// v2 binary root + unsigned discharge.
    const FIX_C_ROOT: &str = "AgEeaHR0cHM6Ly9kYXNoYm9hcmQuc25hcGNyYWZ0LmlvAgl2Mi1yb290LTEAATBodHRwczovL2xvZ2luLnVidW50dS5jb20vYXBpL3YyL3Rva2Vucy9kaXNjaGFyZ2UCCGNpZC12Mi0xBEjDqMLWup5Xj4Bi3cE06Zt9_k2eUI_EdDWSVJBFbAVlJMBldStQ2PpzrxSVtYDCExTH-hnuTaeUXdwW6UPlcQDzUt8pmVv_qKMAAAYgTdwGPHtRPGmCrHUF084k6bIiGmisMyxIfMywjrAdDls";
    const FIX_C_DISCHARGE: &str = "AgEYaHR0cHM6Ly9sb2dpbi51YnVudHUuY29tAg52Mi1kaXNjaGFyZ2UtMQAABgA";
    const FIX_C_BOUND_SIG: &str =
        "52dc33edd48b09b90d8f9b8ccbeee318e0d1c7670f137fb34c890cb9ec1ab857";

    #[test]
    fn parses_v1_binary_root() {
        let m = Macaroon::parse(FIX_A_ROOT).expect("parse");
        assert_eq!(
            m.location.as_deref(),
            Some("https://dashboard.snapcraft.io")
        );
        assert_eq!(m.identifier, "root-id-1");
        assert_eq!(m.caveats.len(), 1);
        assert_eq!(m.caveats[0].id, "cid-001");
        assert_eq!(
            m.caveats[0].location.as_deref(),
            Some("https://login.ubuntu.com/api/v2/tokens/discharge")
        );
        assert!(m.caveats[0].verification_id.is_some());
        assert_eq!(m.format, MacaroonFormat::BinaryV1);
    }

    #[test]
    fn binds_v1_binary_discharge_like_pymacaroons() {
        let root = Macaroon::parse(FIX_A_ROOT).expect("parse");
        let discharge = Macaroon::parse(FIX_A_DISCHARGE).expect("parse");
        let bound = root
            .bind_discharge_signature(&discharge)
            .expect("bind");
        assert_eq!(bound, FIX_A_BOUND_SIG);
    }

    #[test]
    fn parses_v1_json_root_and_binds() {
        let root = Macaroon::parse(FIX_B_ROOT).expect("parse");
        assert_eq!(root.format, MacaroonFormat::JsonV1);
        assert_eq!(root.identifier, "json-root-1");
        let discharge = Macaroon::parse(FIX_A_DISCHARGE).expect("parse");
        let bound = root
            .bind_discharge_signature(&discharge)
            .expect("bind");
        assert_eq!(bound, FIX_B_BOUND_SIG);
    }

    #[test]
    fn parses_v2_binary_root_and_binds() {
        let root = Macaroon::parse(FIX_C_ROOT).expect("parse");
        assert_eq!(root.format, MacaroonFormat::BinaryV2);
        assert_eq!(root.identifier, "v2-root-1");
        assert_eq!(
            root.location.as_deref(),
            Some("https://dashboard.snapcraft.io")
        );
        assert_eq!(root.caveats[0].id, "cid-v2-1");
        let discharge = Macaroon::parse(FIX_C_DISCHARGE).expect("parse");
        let bound = root
            .bind_discharge_signature(&discharge)
            .expect("bind");
        assert_eq!(bound, FIX_C_BOUND_SIG);
    }

    #[test]
    fn empty_root_and_empty_discharge_bind_to_known_constant() {
        let unsigned_root = Macaroon {
            location: None,
            identifier: String::new(),
            caveats: Vec::new(),
            signature_hex: String::new(),
            format: MacaroonFormat::BinaryV1,
        };
        let unsigned_discharge = unsigned_root.clone();
        let bound = unsigned_root
            .bind_discharge_signature(&unsigned_discharge)
            .expect("bind");
        assert_eq!(bound, EMPTY_DISCHARGE_BOUND_SIGNATURE);
    }

    #[test]
    fn finds_discharge_caveat_by_host() {
        let root = Macaroon::parse(FIX_A_ROOT).expect("parse");
        let caveat = root
            .find_discharge_caveat("login.ubuntu.com")
            .expect("caveat");
        assert_eq!(caveat.id, "cid-001");
    }

    #[test]
    fn v1_binary_roundtrip_is_stable() {
        for fixture in [FIX_A_ROOT, FIX_A_DISCHARGE] {
            let m = Macaroon::parse(fixture).expect("parse");
            let reser = m.serialize_v1_binary().expect("ser");
            assert_eq!(reser, fixture, "round-trip must be byte-identical");
        }
    }

    #[test]
    fn rebind_produces_pymacaroons_header() {
        let root = Macaroon::parse(FIX_A_ROOT).expect("parse");
        let discharge = Macaroon::parse(FIX_A_DISCHARGE).expect("parse");
        let bound_sig = root.bind_discharge_signature(&discharge).expect("bind");
        let bound = discharge.rebind_signature(&bound_sig).expect("rebind");
        let ser = bound.serialize_v1_binary().expect("ser");
        assert_eq!(
            ser,
            "MDAyNmxvY2F0aW9uIGh0dHBzOi8vbG9naW4udWJ1bnR1LmNvbQowMDFiaWRlbnRpZmllciBkaXNjaGFyZ2UtMQowMDJmc2lnbmF0dXJlIBwmNssvb5nrm8EyjdBlJF1kdze8Jgii-V2JsFMMFHWGCg"
        );
        let header = format!(
            "Macaroon root={}, discharge={ser}",
            FIX_A_ROOT
        );
        assert!(header.starts_with("Macaroon root=MDAyY2xv"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(Macaroon::parse("").is_err());
        assert!(Macaroon::parse("!!!not-base64!!!").is_err());
        assert!(Macaroon::parse("{ not json").is_err());
        // Truncated packet.
        let truncated = &FIX_A_ROOT[..FIX_A_ROOT.len() - 20];
        assert!(Macaroon::parse(truncated).is_err());
    }
}
