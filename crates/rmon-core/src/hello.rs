//! Windows Hello as a second factor on the stored API key.
//!
//! # Why this exists
//!
//! [`crate::config`] seals the key with DPAPI, which binds it to this user on
//! this machine but not to the user being *present*. Any code already running
//! as you can decrypt it silently. This module closes that gap.
//!
//! # How, given that Hello signs rather than encrypts
//!
//! Hello exposes a TPM-backed key pair whose private half will only sign after
//! a face, fingerprint, or PIN gesture. It offers no encrypt operation, so the
//! signature has to become the secret:
//!
//! 1. A random challenge is generated once and stored in the clear — it is not
//!    a secret, and it is useless without the credential that signs it.
//! 2. Signing that challenge yields 256 bytes that cannot be produced without
//!    a gesture. `RequestSignAsync` is RSASSA-PKCS#1 v1.5, which is
//!    deterministic: the same challenge and credential always give the same
//!    signature. The whole scheme rests on that (verified against this API
//!    before it was written, and relied on by every password manager that
//!    integrates Hello — but note it is a property of the padding scheme
//!    rather than something Microsoft documents as a contract).
//! 3. That signature is handed to `CryptProtectData` as its optional entropy.
//!
//! The result composes rather than replaces: opening the blob needs the user's
//! DPAPI master key *and* a live Hello gesture. Nothing here implements a
//! cipher — the sealing is still the same DPAPI call the unprotected path
//! uses, with different entropy.
//!
//! # What it does not survive
//!
//! Resetting the PIN, re-enrolling biometrics, or clearing the TPM destroys
//! the credential, and with it every blob sealed under it. The plaintext is
//! then gone for good — so callers must treat a failed unseal as "ask the user
//! to enter their key again", never as an error to retry. The gateway cannot
//! reissue a key either; a lost one has to be replaced and the old alias
//! revoked.

use anyhow::{Context, Result, anyhow};
use windows::Security::Credentials::{
    KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows_core::HSTRING;

/// The Hello credential rMon creates. Named per-application: deleting it
/// affects nothing else the user has enrolled.
pub const CREDENTIAL_NAME: &str = "rMon.analyze";

/// Challenge length. Only needs to be long enough not to collide with another
/// application's challenge under the same credential, which is already
/// impossible given the credential is ours alone.
pub const CHALLENGE_LEN: usize = 32;

/// Whether this machine can gate a secret behind Hello.
///
/// False on a machine with no PIN or biometric enrolled, which is a normal
/// state rather than an error — the caller falls back to plain DPAPI.
pub fn is_available() -> bool {
    match KeyCredentialManager::IsSupportedAsync() {
        Ok(op) => block(op).unwrap_or(false),
        Err(_) => false,
    }
}

/// A fresh random challenge, from the system RNG.
pub fn new_challenge() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; CHALLENGE_LEN];
    // SAFETY: `buf` is a live, correctly sized slice for the duration.
    let status = unsafe { BCryptGenRandom(None, &mut buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status.is_err() {
        return Err(anyhow!("BCryptGenRandom failed: {status:?}"));
    }
    Ok(buf)
}

/// Signs `challenge` with the Hello credential, prompting the user.
///
/// `create` decides what happens when the credential does not exist yet:
/// sealing creates it, unsealing must not, because a missing credential at
/// unseal time means the old one was destroyed and silently minting a
/// replacement would produce a different signature and a confusing "wrong
/// key" rather than an honest "this can no longer be opened".
///
/// **Blocks on user interaction.** Never call this on a UI thread.
pub fn sign(challenge: &[u8], create: bool) -> Result<Vec<u8>> {
    let name = HSTRING::from(CREDENTIAL_NAME);

    let opened = block(KeyCredentialManager::OpenAsync(&name)?)?;
    let credential = match opened.Status()? {
        KeyCredentialStatus::Success => opened.Credential()?,
        KeyCredentialStatus::NotFound if create => {
            let created = block(KeyCredentialManager::RequestCreateAsync(
                &name,
                KeyCredentialCreationOption::ReplaceExisting,
            )?)?;
            match created.Status()? {
                KeyCredentialStatus::Success => created.Credential()?,
                other => {
                    return Err(anyhow!(
                        "Windows Hello declined to create a credential: {other:?}"
                    ));
                }
            }
        }
        KeyCredentialStatus::NotFound => {
            return Err(anyhow!(
                "the Windows Hello credential for rMon no longer exists — \
                 a PIN reset, biometric re-enrolment, or TPM clear destroys it, \
                 and the key it protected cannot be recovered"
            ));
        }
        other => return Err(anyhow!("Windows Hello is unavailable: {other:?}")),
    };

    let buffer = CryptographicBuffer::CreateFromByteArray(challenge)
        .context("wrapping the challenge for Windows Hello")?;
    let operation = block(credential.RequestSignAsync(&buffer)?)?;
    match operation.Status()? {
        KeyCredentialStatus::Success => {}
        KeyCredentialStatus::UserCanceled => return Err(anyhow!("Windows Hello was cancelled")),
        other => return Err(anyhow!("Windows Hello did not sign: {other:?}")),
    }

    let mut signature = windows_core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&operation.Result()?, &mut signature)
        .context("reading the Windows Hello signature")?;
    let signature = signature.to_vec();
    if signature.is_empty() {
        return Err(anyhow!("Windows Hello returned an empty signature"));
    }
    Ok(signature)
}

/// Removes rMon's Hello credential.
///
/// Anything sealed under it becomes permanently unreadable, so this is only
/// for the path where the user has already been told that.
pub fn delete_credential() -> Result<()> {
    block_action(KeyCredentialManager::DeleteAsync(&HSTRING::from(
        CREDENTIAL_NAME,
    ))?)
}

/// Blocks on a WinRT async operation without pulling in an executor.
///
/// The completion handler fires on a system thread pool thread; this parks the
/// caller on a channel until it does. WinRT invokes the handler immediately if
/// the operation already finished, so there is no race with a fast completion.
fn block<T>(operation: windows_future::IAsyncOperation<T>) -> Result<T>
where
    T: windows_core::RuntimeType + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    operation.SetCompleted(&windows_future::AsyncOperationCompletedHandler::<T>::new(
        move |_op, _status| {
            let _ = tx.send(());
            Ok(())
        },
    ))?;
    rx.recv()
        .map_err(|_| anyhow!("the Windows Hello operation never completed"))?;
    Ok(operation.GetResults()?)
}

/// [`block`] for an operation that yields nothing.
fn block_action(action: windows_future::IAsyncAction) -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    action.SetCompleted(&windows_future::AsyncActionCompletedHandler::new(
        move |_action, _status| {
            let _ = tx.send(());
            Ok(())
        },
    ))?;
    rx.recv()
        .map_err(|_| anyhow!("the Windows Hello operation never completed"))?;
    Ok(action.GetResults()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_random_and_the_right_length() {
        let a = new_challenge().unwrap();
        let b = new_challenge().unwrap();
        assert_eq!(a.len(), CHALLENGE_LEN);
        assert_ne!(a, b, "two challenges must not collide");
        assert!(
            a.iter().any(|&b| b != 0),
            "challenge must not be all zeroes"
        );
    }

    /// `is_available` must answer rather than panic or hang on any machine,
    /// including one with no Hello enrolled and no TPM.
    #[test]
    fn availability_is_answerable_without_a_prompt() {
        let _ = is_available();
    }
}
