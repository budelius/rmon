//! The analyze tab's credential editor: gateway key, model, and endpoint.
//!
//! Kept apart from the settings tab that hosts it because the same widget is
//! drawn in two places — inline on the analyze tab when there is nothing
//! configured yet, and under Settings once there is. Someone who lands on
//! "no API key" should be able to fix it there rather than be told where to
//! go.
//!
//! The editor holds the key as plaintext in its text buffer only while it is
//! being typed. On save it goes straight into [`rmon_core::config`], which
//! seals it before it reaches disk.

use std::sync::mpsc;

use eframe::egui;
use rmon_core::config::{self, Settings};

/// A masked placeholder shown in place of a key that is already stored.
///
/// The stored key is deliberately never decrypted for display. Showing it
/// would put the plaintext on screen and in the frame buffer for a value the
/// user cannot do anything useful with — they can replace it or clear it, and
/// both work without ever reading it back.
const KEPT: &str = "••••••••••••••••  (stored)";

pub struct CredentialsEditor {
    settings: Settings,
    /// What the user has typed since the last save. Empty means "leave the
    /// stored key alone", which is why clearing needs its own button.
    key_input: String,
    model_input: String,
    base_url_input: String,
    /// Result of the last save or model fetch, shown until the next one.
    status: Option<Status>,
    /// Model ids from the gateway, once fetched.
    models: Vec<String>,
    models_rx: Option<mpsc::Receiver<Result<Vec<String>, String>>>,
}

enum Status {
    Ok(String),
    Err(String),
}

impl CredentialsEditor {
    /// Loads the saved settings. A config that will not parse is surfaced as
    /// an error the user can see rather than being replaced with defaults,
    /// which would quietly discard a key.
    pub fn new() -> Self {
        let (settings, status) = match config::load() {
            Ok(s) => (s, None),
            Err(e) => (Settings::default(), Some(Status::Err(format!("{e:#}")))),
        };
        Self {
            model_input: settings.llm.model.clone().unwrap_or_default(),
            base_url_input: settings.llm.base_url.clone().unwrap_or_default(),
            settings,
            key_input: String::new(),
            status: None.or(status),
            models: Vec::new(),
            models_rx: None,
        }
    }

    /// Whether a model fetch is in flight, so the app keeps repainting.
    pub fn fetching(&self) -> bool {
        self.models_rx.is_some()
    }

    /// Collects a finished model fetch. Called once per frame from the app's
    /// tick, like every other background result.
    pub fn poll(&mut self) {
        let Some(rx) = &self.models_rx else { return };
        match rx.try_recv() {
            Ok(Ok(models)) => {
                self.status = Some(Status::Ok(format!("{} models offered", models.len())));
                self.models = models;
                self.models_rx = None;
            }
            Ok(Err(e)) => {
                self.status = Some(Status::Err(e));
                self.models_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.models_rx = None,
        }
    }

    /// Draws the editor. Returns true if the stored settings changed, so the
    /// caller can re-resolve whatever depends on them.
    #[must_use]
    pub fn draw(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;

        ui.horizontal(|ui| {
            ui.label("API key:");
            let hint = if self.settings.llm.has_api_key() {
                KEPT
            } else {
                "paste a Passiv gateway key"
            };
            ui.add(
                egui::TextEdit::singleline(&mut self.key_input)
                    .password(true)
                    .hint_text(hint)
                    .desired_width(320.0),
            );
        });

        ui.horizontal(|ui| {
            ui.label("Model:");
            ui.add(
                egui::TextEdit::singleline(&mut self.model_input)
                    .hint_text("e.g. claude-opus")
                    .desired_width(200.0),
            );

            // Listing models needs a key and an endpoint but not a saved
            // config, so it works while first filling the form in.
            let can_fetch = self.fetch_key().is_some() && self.models_rx.is_none();
            if ui
                .add_enabled(can_fetch, egui::Button::new("fetch from gateway"))
                .on_hover_text("GET /v1/models — asks the gateway what this key may use")
                .clicked()
            {
                self.start_fetch();
            }
            if self.models_rx.is_some() {
                ui.spinner();
            }
        });

        if !self.models.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label("offered:");
                for id in &self.models {
                    if ui.selectable_label(self.model_input == *id, id).clicked() {
                        self.model_input = id.clone();
                    }
                }
            });
        }

        ui.horizontal(|ui| {
            ui.label("Endpoint:");
            ui.add(
                egui::TextEdit::singleline(&mut self.base_url_input)
                    .hint_text(rmon_agent::DEFAULT_BASE_URL)
                    .desired_width(320.0),
            );
            // A key minted on one gateway is not valid on the other, so the
            // choice is worth making explicit rather than typing from memory.
            for (label, url) in rmon_agent::ENDPOINTS {
                let selected = self.base_url_input == url
                    || (self.base_url_input.trim().is_empty()
                        && url == rmon_agent::DEFAULT_BASE_URL);
                if ui
                    .selectable_label(selected, label)
                    .on_hover_text(url)
                    .clicked()
                {
                    self.base_url_input = url.to_string();
                    // The offered models belong to the old endpoint.
                    self.models.clear();
                }
            }
        });

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Save").clicked() {
                changed = self.save();
            }
            let stored = self.settings.llm.has_api_key();
            if ui
                .add_enabled(stored, egui::Button::new("Clear key"))
                .on_hover_text("Forgets the stored key. The gateway still holds it — revoke there.")
                .clicked()
            {
                self.key_input.clear();
                changed = self.clear_key();
            }
        });

        match &self.status {
            Some(Status::Ok(msg)) => {
                ui.colored_label(super::OK_COLOR, msg);
            }
            Some(Status::Err(msg)) => {
                ui.colored_label(super::BAD_COLOR, msg);
            }
            None => {}
        }

        ui.add_space(2.0);
        ui.weak(
            "Stored encrypted for your Windows account under %APPDATA%\\rMon. \
             Environment variables (RMON_LLM_API_KEY, RMON_LLM_MODEL) still work \
             as a fallback when nothing is saved here.",
        );

        changed
    }

    /// The key to authenticate a model fetch with: what is being typed if
    /// anything, else what is already stored.
    fn fetch_key(&self) -> Option<String> {
        let typed = self.key_input.trim();
        if !typed.is_empty() {
            return Some(typed.to_string());
        }
        self.settings.llm.api_key().ok().flatten()
    }

    fn base_url(&self) -> String {
        let typed = self.base_url_input.trim();
        if typed.is_empty() {
            rmon_agent::DEFAULT_BASE_URL.to_string()
        } else {
            typed.to_string()
        }
    }

    fn start_fetch(&mut self) {
        let Some(key) = self.fetch_key() else { return };
        let base = self.base_url();
        let (tx, rx) = mpsc::channel();
        self.models_rx = Some(rx);
        // A gateway round-trip on the UI thread would stall the sampling
        // tick that shares it.
        std::thread::spawn(move || {
            let result = rmon_agent::chat::list_models(&base, &key, 30)
                .map_err(|e| format!("could not list models: {e:#}"));
            let _ = tx.send(result);
        });
    }

    fn save(&mut self) -> bool {
        let typed = self.key_input.trim().to_string();
        if !typed.is_empty()
            && let Err(e) = self.settings.llm.set_api_key(&typed)
        {
            self.status = Some(Status::Err(format!("could not encrypt the key: {e:#}")));
            return false;
        }

        self.settings.llm.model = non_empty(&self.model_input);
        self.settings.llm.base_url = non_empty(&self.base_url_input);

        match config::save(&self.settings) {
            Ok(()) => {
                self.key_input.clear();
                self.status = Some(Status::Ok("saved".into()));
                true
            }
            Err(e) => {
                self.status = Some(Status::Err(format!("could not save: {e:#}")));
                false
            }
        }
    }

    fn clear_key(&mut self) -> bool {
        // Cannot fail: clearing takes the blank-input branch, which only
        // assigns None.
        let _ = self.settings.llm.set_api_key("");
        match config::save(&self.settings) {
            Ok(()) => {
                self.status = Some(Status::Ok("key forgotten".into()));
                true
            }
            Err(e) => {
                self.status = Some(Status::Err(format!("could not save: {e:#}")));
                false
            }
        }
    }
}

fn non_empty(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}
