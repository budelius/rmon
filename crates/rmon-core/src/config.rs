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
    /// The same key sealed so that opening it also needs a Windows Hello
    /// gesture. Mutually exclusive with [`Self::api_key_sealed`]: leaving the
    /// plain blob behind when Hello is turned on would keep a way past the
    /// gesture, which is the entire point of turning it on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_hello: Option<HelloSealed>,
}

/// A key sealed under DPAPI with a Windows Hello signature as its entropy.
///
/// Neither field is a secret on its own. The challenge is random public data,
/// and the blob cannot be opened without both this user's DPAPI master key and
/// a signature only a live gesture produces.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HelloSealed {
    /// Hex; signed to derive the entropy.
    pub challenge: String,
    /// Hex; the DPAPI ciphertext.
    pub blob: String,
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
        let bytes = unseal(
            &from_hex(sealed).context("stored key is not valid hex")?,
            ENTROPY,
        )
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
        self.api_key_sealed = Some(to_hex(&seal(key.as_bytes(), ENTROPY)?));
        Ok(())
    }

    /// Whether a key is stored in either form, without decrypting it.
    pub fn has_api_key(&self) -> bool {
        self.api_key_sealed.is_some() || self.api_key_hello.is_some()
    }

    /// Whether reading the key needs a Windows Hello gesture.
    pub fn requires_hello(&self) -> bool {
        self.api_key_hello.is_some()
    }

    /// Seals `key` behind Windows Hello, prompting for a gesture.
    ///
    /// Clears the plain DPAPI blob on success: keeping it would leave a copy
    /// readable without the gesture, defeating the option the user just chose.
    /// A blank key clears both.
    ///
    /// **Blocks on user interaction.** Never call this on a UI thread.
    pub fn set_api_key_with_hello(&mut self, key: &str) -> Result<()> {
        let key = key.trim();
        if key.is_empty() {
            self.api_key_sealed = None;
            self.api_key_hello = None;
            return Ok(());
        }

        let challenge = crate::hello::new_challenge()?;
        let signature = crate::hello::sign(&challenge, true)?;
        let blob = seal(key.as_bytes(), &signature)?;

        self.api_key_hello = Some(HelloSealed {
            challenge: to_hex(&challenge),
            blob: to_hex(&blob),
        });
        self.api_key_sealed = None;
        Ok(())
    }

    /// Decrypts the Hello-sealed key, prompting for a gesture.
    ///
    /// The credential is never created here — see [`crate::hello::sign`] for
    /// why a missing one has to be an error rather than a fresh enrolment.
    ///
    /// **Blocks on user interaction.** Never call this on a UI thread.
    pub fn unlock_with_hello(&self) -> Result<String> {
        let sealed = self
            .api_key_hello
            .as_ref()
            .ok_or_else(|| anyhow!("no Windows Hello key is stored"))?;

        let challenge =
            from_hex(&sealed.challenge).context("stored Hello challenge is not valid hex")?;
        let blob = from_hex(&sealed.blob).context("stored Hello blob is not valid hex")?;
        let signature = crate::hello::sign(&challenge, false)?;

        let bytes = unseal(&blob, &signature).context(
            "the stored key could not be decrypted — the Windows Hello credential              that sealed it has been replaced, so the key must be entered again",
        )?;
        String::from_utf8(bytes).context("stored key is not valid UTF-8")
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
fn seal(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: both input blobs borrow slices that outlive the call, and `out`
    // is filled in by DPAPI with a LocalAlloc buffer that `take` copies and
    // frees.
    unsafe {
        let input = blob(plaintext);
        let entropy = blob(entropy);
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
fn unseal(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: as in `seal`.
    unsafe {
        let input = blob(ciphertext);
        let entropy = blob(entropy);
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

    /// Whether this machine can seal anything at all.
    ///
    /// DPAPI needs a loaded user profile. CI runners have none, so
    /// `CryptProtectData` fails there with "DPAPI could not encrypt the
    /// key", and a test that unwrapped it was asserting the runner's
    /// configuration rather than rMon's behaviour. Where sealing is
    /// impossible the tests below cannot say anything, so they say that
    /// out loud instead of failing the build — and still run for real on
    /// every machine where the feature actually works.
    fn can_seal() -> bool {
        match seal(b"probe", ENTROPY) {
            Ok(_) => true,
            Err(e) => {
                println!("skipping: this machine cannot seal with DPAPI ({e:#})");
                false
            }
        }
    }

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
        if !can_seal() {
            return;
        }
        let mut llm = LlmSettings::default();
        llm.set_api_key("sk-example-value").unwrap();

        // The plaintext must not be recoverable from the stored form.
        let sealed = llm.api_key_sealed.clone().unwrap();
        assert!(!sealed.contains(&to_hex(b"sk-example-value")));

        assert_eq!(llm.api_key().unwrap().as_deref(), Some("sk-example-value"));
    }

    #[test]
    fn blank_key_clears_rather_than_sealing_empty() {
        if !can_seal() {
            return;
        }
        let mut llm = LlmSettings::default();
        llm.set_api_key("sk-real").unwrap();
        llm.set_api_key("   ").unwrap();
        assert!(!llm.has_api_key());
        assert_eq!(llm.api_key().unwrap(), None);
    }

    #[test]
    fn key_is_trimmed_because_pasted_values_carry_whitespace() {
        if !can_seal() {
            return;
        }
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
        if !can_seal() {
            return;
        }
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

    /// The property the whole Hello design rests on: entropy is not
    /// decoration. A blob sealed under one signature must be unopenable under
    /// any other, or the gesture gates nothing.
    #[test]
    fn a_blob_is_unopenable_under_different_entropy() {
        if !can_seal() {
            return;
        }
        let signature_a = vec![0xAB; 256];
        let signature_b = vec![0xCD; 256];

        let blob = seal(b"sk-hello-protected", &signature_a).unwrap();

        assert_eq!(
            unseal(&blob, &signature_a).unwrap(),
            b"sk-hello-protected",
            "the right entropy must still open it"
        );
        assert!(
            unseal(&blob, &signature_b).is_err(),
            "a different signature must not open it"
        );
        assert!(
            unseal(&blob, ENTROPY).is_err(),
            "the plain static entropy must not open a Hello-sealed blob"
        );
    }

    /// And the converse: turning Hello on must not leave the plain blob
    /// behind as a way around the gesture.
    #[test]
    fn the_two_seal_forms_are_mutually_exclusive() {
        if !can_seal() {
            return;
        }
        let mut llm = LlmSettings::default();
        llm.set_api_key("sk-plain").unwrap();
        assert!(llm.has_api_key() && !llm.requires_hello());

        // Simulate what set_api_key_with_hello stores, without a gesture.
        llm.api_key_hello = Some(HelloSealed {
            challenge: to_hex(&[7u8; 32]),
            blob: to_hex(&seal(b"sk-hello", &[9u8; 256]).unwrap()),
        });
        llm.api_key_sealed = None;

        assert!(llm.requires_hello());
        assert!(llm.has_api_key());
        assert_eq!(
            llm.api_key().unwrap(),
            None,
            "with no plain blob there is nothing to read without a gesture"
        );
    }

    #[test]
    fn hello_settings_serialise_without_the_plaintext_and_round_trip() {
        let mut settings = Settings::default();
        settings.llm.api_key_hello = Some(HelloSealed {
            challenge: to_hex(&[1u8; 32]),
            blob: to_hex(&seal(b"sk-secret-hello-key", &[2u8; 256]).unwrap()),
        });

        let json = serde_json::to_string_pretty(&settings).unwrap();
        assert!(!json.contains("sk-secret-hello-key"), "{json}");
        assert!(json.contains("api_key_hello"));
        assert!(
            !json.contains("api_key_sealed"),
            "absent field must stay absent"
        );

        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, settings);
        assert!(back.llm.requires_hello());
    }

    #[test]
    fn unlocking_without_a_stored_hello_key_is_an_error_not_a_prompt() {
        let llm = LlmSettings::default();
        let err = llm.unlock_with_hello().unwrap_err();
        assert!(
            format!("{err:#}").contains("no Windows Hello key"),
            "{err:#}"
        );
    }

    /// A config written by a build that had no Hello support must still load.
    #[test]
    fn configs_without_the_hello_field_still_load() {
        let settings: Settings =
            serde_json::from_str(r#"{"llm":{"api_key_sealed":"00","model":"m"}}"#).unwrap();
        assert!(!settings.llm.requires_hello());
        assert!(settings.llm.has_api_key());
    }
}
