//! Persisted user settings: `%APPDATA%\rMon\config.json`.
//!
//! Only the analyze tab needs this today — somewhere to keep the gateway
//! credentials it was previously reading from environment variables, so the
//! user can type a key once instead of running `setx` and restarting.
//!
//! # What the encryption does and does not buy
//!
//! The API key is sealed with DPAPI (`CryptProtectData`) under the current
//! user's master key, with a fixed application entropy blob mixed in. That
//! makes the file useless to another *user* and useless on another *machine*:
//! copying `config.json` to a different account or box yields ciphertext
//! nobody there can open.
//!
//! It does not make the key safe from code already running as this user. Such
//! code can call `CryptUnprotectData` with the same entropy — which is
//! compiled into the binary and therefore not a secret — exactly as rMon does.
//! The threat this addresses is a config file read at rest (backup, sync
//! folder, support bundle, shoulder surf), not local compromise. Anything
//! stronger would need a credential the user supplies each launch, which is
//! the opposite of what this feature is for.
//!
//! Elevation is not a factor: an elevated rMon runs as the same user SID and
//! opens the same blob. Launching rMon as a *different* administrator account
//! would not, and that reads as an error rather than as a missing key.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

/// Mixed into every seal so a bare `CryptUnprotectData` over a stolen file —
/// by something that does not know it came from rMon — fails. Not a secret;
/// see the module docs.
const ENTROPY: &[u8] = b"rMon.analyze.credentials.v1";

/// Settings as they sit on disk.
///
/// Every field is optional and unknown fields are ignored, so a config written
/// by a newer rMon still loads in an older one, and a partially filled config
/// is a normal state rather than a parse error.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    pub llm: LlmSettings,
}

/// Credentials and routing for the analyze tab's agent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LlmSettings {
    /// DPAPI ciphertext, hex encoded. Never the key itself — a plaintext key
    /// must not reach this struct's `Serialize`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_sealed: Option<String>,
    /// Model id as the gateway names it, e.g. `claude-opus`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// OpenAI-compatible `/v1` base. Absent means the built-in default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
}

impl LlmSettings {
    /// Decrypts the stored key, or `None` if there is none.
    ///
    /// A blob that fails to open — different user, corrupt file, restored from
    /// another machine — is reported as an error rather than silently treated
    /// as "no key", because the two call for different fixes: one means type
    /// your key in, the other means this key can never be recovered here.
    pub fn api_key(&self) -> Result<Option<String>> {
        let Some(sealed) = &self.api_key_sealed else {
            return Ok(None);
        };
        let bytes = unseal(&from_hex(sealed).context("stored key is not valid hex")?)
            .context("stored key could not be decrypted for this user on this machine")?;
        let key = String::from_utf8(bytes).context("stored key is not valid UTF-8")?;
        Ok(Some(key).filter(|k| !k.trim().is_empty()))
    }

    /// Seals `key` into [`Self::api_key_sealed`], or clears it when blank.
    pub fn set_api_key(&mut self, key: &str) -> Result<()> {
        let key = key.trim();
        if key.is_empty() {
            self.api_key_sealed = None;
            return Ok(());
        }
        self.api_key_sealed = Some(to_hex(&seal(key.as_bytes())?));
        Ok(())
    }

    /// Whether a key is stored, without decrypting it.
    pub fn has_api_key(&self) -> bool {
        self.api_key_sealed.is_some()
    }
}

/// `%APPDATA%\rMon\config.json`.
pub fn path() -> Result<PathBuf> {
    let appdata = std::env::var("APPDATA")
        .map_err(|_| anyhow!("APPDATA is not set, so there is nowhere to keep settings"))?;
    Ok(PathBuf::from(appdata).join("rMon").join("config.json"))
}

/// Reads settings, treating "no file yet" as defaults.
///
/// A malformed file is an error rather than a silent reset: overwriting a
/// config the user hand-edited, because rMon could not parse it, loses their
/// key with no way to tell them why.
pub fn load() -> Result<Settings> {
    let path = path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Writes settings, creating `%APPDATA%\rMon` if needed.
///
/// Writes a temporary file and renames it over the target, so an interrupted
/// write leaves the previous config intact rather than a truncated one.
pub fn save(settings: &Settings) -> Result<()> {
    let path = path()?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("settings path has no parent directory"))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let text = serde_json::to_string_pretty(settings).context("serialising settings")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// DPAPI-encrypts `plaintext` for the current user.
fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: both input blobs borrow slices that outlive the call, and `out`
    // is filled in by DPAPI with a LocalAlloc buffer that `take` copies and
    // frees.
    unsafe {
        let input = blob(plaintext);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .context("DPAPI could not encrypt the key")?;
        Ok(take(out))
    }
}

/// DPAPI-decrypts what [`seal`] produced.
fn unseal(ciphertext: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: as in `seal`.
    unsafe {
        let input = blob(ciphertext);
        let entropy = blob(ENTROPY);
        let mut out = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(
            &input,
            None,
            Some(&entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
        .context("DPAPI could not decrypt the key")?;
        Ok(take(out))
    }
}

/// Borrows `data` as a DPAPI blob. The blob must not outlive `data`.
fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    }
}

/// Copies a blob DPAPI allocated and frees the original.
///
/// # Safety
///
/// `out` must be a blob filled in by a successful DPAPI call, whose `pbData`
/// came from `LocalAlloc` and has not already been freed.
unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    unsafe {
        let copied = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut _)));
        copied
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn from_hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err(anyhow!("hex string has an odd length"));
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| anyhow!("hex string is not ASCII"))?;
            u8::from_str_radix(s, 16).map_err(|_| anyhow!("{s:?} is not a hex byte"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_every_byte_value() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&all)).unwrap(), all);
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert!(from_hex("abc").is_err(), "odd length");
        assert!(from_hex("zz").is_err(), "not hex digits");
    }

    #[test]
    fn sealed_key_round_trips_through_dpapi() {
        let mut llm = LlmSettings::default();
        llm.set_api_key("sk-example-value").unwrap();

        // The plaintext must not be recoverable from the stored form.
        let sealed = llm.api_key_sealed.clone().unwrap();
        assert!(!sealed.contains(&to_hex(b"sk-example-value")));

        assert_eq!(llm.api_key().unwrap().as_deref(), Some("sk-example-value"));
    }

    #[test]
    fn blank_key_clears_rather_than_sealing_empty() {
        let mut llm = LlmSettings::default();
        llm.set_api_key("sk-real").unwrap();
        llm.set_api_key("   ").unwrap();
        assert!(!llm.has_api_key());
        assert_eq!(llm.api_key().unwrap(), None);
    }

    #[test]
    fn key_is_trimmed_because_pasted_values_carry_whitespace() {
        let mut llm = LlmSettings::default();
        llm.set_api_key("  sk-padded\n").unwrap();
        assert_eq!(llm.api_key().unwrap().as_deref(), Some("sk-padded"));
    }

    #[test]
    fn corrupt_blob_is_an_error_not_a_missing_key() {
        let llm = LlmSettings {
            api_key_sealed: Some(to_hex(b"not a dpapi blob")),
            ..Default::default()
        };
        assert!(llm.api_key().is_err());
    }

    #[test]
    fn serialised_settings_never_contain_the_plaintext_key() {
        let mut settings = Settings::default();
        settings.llm.set_api_key("sk-secret-do-not-leak").unwrap();
        settings.llm.model = Some("claude-opus".into());

        let json = serde_json::to_string_pretty(&settings).unwrap();
        assert!(!json.contains("sk-secret-do-not-leak"), "{json}");
        assert!(json.contains("api_key_sealed"));
        assert!(json.contains("claude-opus"));

        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, settings);
        assert_eq!(
            back.llm.api_key().unwrap().as_deref(),
            Some("sk-secret-do-not-leak")
        );
    }

    #[test]
    fn unknown_and_missing_fields_load_as_defaults() {
        let settings: Settings =
            serde_json::from_str(r#"{"llm":{"model":"m","future_field":1},"future":true}"#)
                .unwrap();
        assert_eq!(settings.llm.model.as_deref(), Some("m"));
        assert!(!settings.llm.has_api_key());
        assert_eq!(settings.llm.base_url, None);

        assert_eq!(
            serde_json::from_str::<Settings>("{}").unwrap(),
            Settings::default()
        );
    }
}
