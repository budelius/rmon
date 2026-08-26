//! Build provenance, the About window, and the What's New tab.
//!
//! A version number alone cannot answer "am I running the build I just
//! made?" — during a release cycle several builds share one version. The
//! commit, whether its tree was dirty, and the time the binary was
//! compiled can. `build.rs` stamps all three in.

use eframe::egui;

/// Semantic version from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// UTC time this binary was compiled.
pub const BUILD_TIME: &str = env!("RMON_BUILD_TIME");
/// Short commit hash, or `unknown` outside a git checkout.
pub const GIT_SHA: &str = env!("RMON_GIT_SHA");
/// Whether the working tree had uncommitted changes at build time.
pub const GIT_DIRTY: bool = matches!(env!("RMON_GIT_DIRTY").as_bytes(), b"true");

/// The changelog, embedded so the what's new tab works without needing
/// the repository present.
pub const CHANGELOG: &str = include_str!("../../../CHANGELOG.md");

/// One line for the header: enough to tell two builds apart at a glance.
pub fn short_line() -> String {
    format!(
        "v{VERSION} · {BUILD_TIME}{}",
        if GIT_DIRTY { " · dirty" } else { "" }
    )
}

/// The About window. `open` is the caller's flag, cleared when it closes.
///
/// Deliberately just build provenance: the release notes used to be
/// embedded here too, which made About a scrolling wall that buried the
/// four facts a bug report actually needs. They live in their own tab.
pub fn window(ctx: &egui::Context, open: &mut bool) {
    egui::Window::new("About rMon")
        .open(open)
        .collapsible(false)
        .resizable(true)
        .default_width(460.0)
        .show(ctx, |ui| {
            ui.heading("rMon");
            ui.weak("live process CPU/GPU monitor");
            ui.add_space(8.0);

            egui::Grid::new("about-build")
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Version:");
                    ui.label(VERSION);
                    ui.end_row();

                    ui.label("Built:");
                    ui.label(BUILD_TIME);
                    ui.end_row();

                    ui.label("Commit:");
                    ui.horizontal(|ui| {
                        ui.label(GIT_SHA);
                        if GIT_DIRTY {
                            // Worth saying plainly: the commit does not
                            // describe what is running.
                            ui.colored_label(
                                super::WARN_COLOR,
                                "+ uncommitted changes at build time",
                            );
                        }
                    });
                    ui.end_row();

                    ui.label("Elevated:");
                    if rmon_core::elevate::is_elevated() {
                        ui.colored_label(super::OK_COLOR, "yes");
                    } else {
                        ui.label("no");
                    }
                    ui.end_row();
                });

            ui.add_space(6.0);
            if ui
                .button("📋 Copy build info")
                .on_hover_text("For pasting into a bug report")
                .clicked()
            {
                ui.ctx().copy_text(format!(
                    "rMon {VERSION} built {BUILD_TIME} commit {GIT_SHA}{}",
                    if GIT_DIRTY { " (dirty)" } else { "" }
                ));
            }

            ui.add_space(8.0);
            ui.separator();
            ui.weak("Release notes are in the what's new tab.");
        });
}

/// The changelog section describing `version`, without its own heading, or
/// `None` when the changelog never mentions that version.
///
/// A section is a line starting `## <version>` and runs until the next
/// `## `. Scanning the text rather than parsing markdown is the same
/// trade-off [`draw_notes`] makes.
pub fn release_notes(version: &str) -> Option<&'static str> {
    let heading = format!("\n## {version}");
    let start = CHANGELOG.find(&heading)? + 1;
    let section = &CHANGELOG[start..];
    // Skip the heading line itself.
    let body_at = section.find('\n').map_or(section.len(), |i| i + 1);
    let body = &section[body_at..];
    let end = body.find("\n## ").unwrap_or(body.len());
    Some(body[..end].trim_matches('\n'))
}

/// Persistent tab showing what shipped in *this* build: the running
/// version's own release notes first, the full history collapsed below.
///
/// It keys off `VERSION` rather than simply showing the top of the file,
/// because those are not always the same section. A build made from a tree
/// where the next release's notes are already written would otherwise
/// claim changes the binary does not contain.
pub fn whats_new_tab(ui: &mut egui::Ui) {
    ui.heading(format!("What's new in v{VERSION}"));
    ui.weak(short_line());
    ui.horizontal(|ui| {
        ui.weak("commit:");
        ui.monospace(GIT_SHA);
        if GIT_DIRTY {
            ui.colored_label(super::WARN_COLOR, "dirty build");
        }
    });
    ui.add_space(8.0);

    egui::ScrollArea::vertical()
        .id_salt("whats-new-changelog")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            match release_notes(VERSION) {
                Some(notes) => draw_notes(ui, notes),
                None => {
                    ui.colored_label(
                        super::WARN_COLOR,
                        format!("The changelog has no section for v{VERSION}."),
                    );
                }
            }
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(4.0);
            ui.collapsing("Every release", |ui| draw_notes(ui, CHANGELOG));
        });
}

/// Renders changelog text. Headings are drawn strong so the tab has some
/// structure; everything else is plain wrapped text, because a markdown
/// renderer would be another dependency for notes read once per upgrade.
fn draw_notes(ui: &mut egui::Ui, notes: &str) {
    fn flush(ui: &mut egui::Ui, para: &mut String) {
        let text = para.trim_matches('\n');
        if !text.is_empty() {
            ui.add(egui::Label::new(text.to_string()).wrap());
        }
        para.clear();
    }

    let mut para = String::new();
    for line in notes.lines() {
        if let Some(h) = line
            .strip_prefix("### ")
            .or_else(|| line.strip_prefix("## "))
        {
            flush(ui, &mut para);
            ui.add_space(6.0);
            ui.label(egui::RichText::new(h).strong());
        } else if let Some(h) = line.strip_prefix("# ") {
            flush(ui, &mut para);
            ui.heading(h);
        } else {
            para.push_str(line);
            para.push('\n');
        }
    }
    flush(ui, &mut para);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guards the build.rs contract: if the stamp stops being emitted the
    /// About dialog silently starts lying about which build is running.
    #[test]
    fn build_stamp_is_populated() {
        assert!(!BUILD_TIME.is_empty());
        assert!(BUILD_TIME.ends_with("UTC"), "{BUILD_TIME}");
        assert!(!GIT_SHA.is_empty());
        assert!(!VERSION.is_empty());
    }

    /// The whole point of the what's new tab is that it describes the
    /// build you are running. A version bump with no changelog entry
    /// breaks that silently, so make it break the build instead.
    #[test]
    fn the_running_version_has_release_notes() {
        assert!(CHANGELOG.contains("# Changelog"));
        let notes = release_notes(VERSION)
            .unwrap_or_else(|| panic!("CHANGELOG.md has no `## {VERSION}` section"));
        assert!(!notes.trim().is_empty(), "the v{VERSION} section is empty");
    }

    #[test]
    fn release_notes_stop_at_the_next_section() {
        let notes = release_notes("0.1.0").expect("0.1.0 section");
        assert!(
            !notes.contains("\n## "),
            "section bled into its neighbour: {notes}"
        );
        assert_eq!(release_notes("9.9.9"), None);
    }

    #[test]
    fn changelog_leads_with_the_running_version() {
        let newest = CHANGELOG
            .find(&format!("\n## {VERSION}"))
            .expect("current version section");
        let oldest = CHANGELOG.find("\n## 0.1.0").expect("0.1.0 section");
        assert!(newest <= oldest, "newest entry must come first");
    }

    #[test]
    fn short_line_identifies_the_build() {
        let line = short_line();
        assert!(line.contains(VERSION), "{line}");
        assert!(line.contains(BUILD_TIME), "{line}");
        assert_eq!(line.contains("dirty"), GIT_DIRTY, "{line}");
    }
}
