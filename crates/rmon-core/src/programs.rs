//! Installed-program inventory and live process attribution.
//!
//! Windows does not have one authoritative package database. The inventory
//! below reads the same per-machine/per-user 32-bit and 64-bit Uninstall
//! registry views used by the classic Programs and Features UI. That covers
//! ordinary Win32/MSI applications, but not every portable executable or
//! every Store package. Likewise, `ParentKeyName` records a few installer
//! relationships (usually updates/bundles), not a complete dependency graph.
//! The API keeps those limits explicit instead of inventing certainty.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
};

use crate::ProcessSample;

const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall";
const USAGE_FILE_VERSION: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
struct ProgramUsageFile {
    version: u32,
    last_observed: HashMap<String, DateTime<Utc>>,
}

/// Whether an uninstall entry applies to this user or the whole machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramScope {
    CurrentUser,
    AllUsers,
}

impl ProgramScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CurrentUser => "current user",
            Self::AllUsers => "all users",
        }
    }
}

/// One entry from a Windows Uninstall registry view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledProgram {
    /// Stable identity within this inventory: scope/view/registry key.
    pub id: String,
    /// Leaf key under `...\CurrentVersion\Uninstall`; used by the limited
    /// `ParentKeyName` relationship Windows installers expose.
    pub registry_key: String,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    pub install_date: Option<String>,
    pub display_icon: Option<String>,
    pub comments: Option<String>,
    pub website: Option<String>,
    pub estimated_size_bytes: Option<u64>,
    pub scope: ProgramScope,
    /// `"64-bit"` or `"32-bit"` registry view; this describes installer
    /// registration, not necessarily every executable shipped by the app.
    pub registry_view: String,
    pub uninstall_command: Option<String>,
    pub quiet_uninstall_command: Option<String>,
    pub system_component: bool,
    pub update_or_hotfix: bool,
    pub windows_installer: bool,
    pub no_remove: bool,
    pub parent_key_name: Option<String>,
}

impl InstalledProgram {
    /// True when Windows exposes a removal command and the entry has not
    /// explicitly disabled removal. This says the app *can* be removed, not
    /// that removing it is safe.
    pub fn has_uninstaller(&self) -> bool {
        !self.no_remove
            && (self.quiet_uninstall_command.is_some() || self.uninstall_command.is_some())
    }

    /// Metadata-only reasons to look more closely. These are intentionally
    /// phrased as missing/odd evidence, never as a malware verdict.
    pub fn attention_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.publisher.is_none() {
            reasons.push("publisher is not recorded by the installer".to_string());
        }
        if let Some(location) = self.install_location.as_deref() {
            let location = normalize_path(location);
            if is_transient_path(&location) {
                reasons.push("install location is under a temporary or Downloads directory".into());
            }
            if location.starts_with(r"\\") {
                reasons.push("install location is a network path".into());
            }
        }
        reasons
    }
}

/// Best-effort inventory result. One unreadable registry view/key does not
/// discard entries from the others.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstalledProgramsScan {
    pub programs: Vec<InstalledProgram>,
    pub warnings: Vec<String>,
}

/// A relationship Windows explicitly recorded between uninstall entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRelationship {
    pub parent_id: String,
    pub dependent_id: String,
    /// Currently always `ParentKeyName`; named so more authoritative sources
    /// can be added later without flattening them into the same confidence.
    pub source: String,
}

/// How one live process maps to installed software.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessProgramLink {
    pub pid: u32,
    /// Program whose install directory/icon directly contains the image.
    pub direct_program_id: Option<String>,
    /// Nearest program-owned ancestor process, excluding this process. This
    /// is the evidence behind “Warp launched find.exe”, and is separate from
    /// package ownership because the child may belong to another package.
    pub launcher_program_id: Option<String>,
}

/// Current inclusive resource use for one installed program.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgramActivity {
    pub program_id: String,
    /// Executables directly matched to the installed program.
    pub direct_pids: Vec<u32>,
    /// Processes whose nearest program-owned ancestor belongs to this app.
    pub launched_pids: Vec<u32>,
    /// Sum over the union of direct and launched pids. Inclusive totals are
    /// useful for launchers/IDEs/terminals, but can overlap another app's
    /// direct total; the UI labels them accordingly.
    pub cpu_percent: f32,
    pub gpu_percent: f32,
    pub memory_bytes: u64,
}

impl ProgramActivity {
    pub fn active(&self) -> bool {
        !self.direct_pids.is_empty() || !self.launched_pids.is_empty()
    }

    pub fn process_count(&self) -> usize {
        self.direct_pids
            .iter()
            .chain(&self.launched_pids)
            .copied()
            .collect::<HashSet<_>>()
            .len()
    }

    pub fn all_pids(&self) -> HashSet<u32> {
        self.direct_pids
            .iter()
            .chain(&self.launched_pids)
            .copied()
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProgramAttribution {
    pub links: Vec<ProcessProgramLink>,
    pub activities: Vec<ProgramActivity>,
}

/// `%APPDATA%\rMon\program-usage.json`.
fn usage_path() -> Result<PathBuf> {
    let mut path = crate::config::path()?;
    path.set_file_name("program-usage.json");
    Ok(path)
}

/// Loads timestamps at which rMon last observed a live process attributable
/// to each installed-program id. This is rMon's own observation history, not
/// a Windows-provided last-used database.
pub fn load_program_usage() -> Result<HashMap<String, DateTime<Utc>>> {
    let path = usage_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let file: ProgramUsageFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if file.version != USAGE_FILE_VERSION {
        return Err(anyhow!(
            "unsupported program usage file version {}",
            file.version
        ));
    }
    Ok(file.last_observed)
}

/// Atomically persists rMon's program observation timestamps. No command
/// lines, process paths, or credentials are stored in this file.
pub fn save_program_usage(last_observed: &HashMap<String, DateTime<Utc>>) -> Result<()> {
    let path = usage_path()?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("program usage path has no parent directory"))?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let file = ProgramUsageFile {
        version: USAGE_FILE_VERSION,
        last_observed: last_observed.clone(),
    };
    let text = serde_json::to_string_pretty(&file).context("serialising program usage")?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Reads all four conventional Uninstall registry views.
pub fn list_installed_programs() -> InstalledProgramsScan {
    let sources = [
        (
            HKEY_LOCAL_MACHINE,
            ProgramScope::AllUsers,
            KEY_WOW64_64KEY,
            "64-bit",
        ),
        (
            HKEY_LOCAL_MACHINE,
            ProgramScope::AllUsers,
            KEY_WOW64_32KEY,
            "32-bit",
        ),
        (
            HKEY_CURRENT_USER,
            ProgramScope::CurrentUser,
            KEY_WOW64_64KEY,
            "64-bit",
        ),
        (
            HKEY_CURRENT_USER,
            ProgramScope::CurrentUser,
            KEY_WOW64_32KEY,
            "32-bit",
        ),
    ];

    let mut scan = InstalledProgramsScan::default();
    for (hive, scope, view_flag, view_name) in sources {
        let root = RegKey::predef(hive);
        let key = match root.open_subkey_with_flags(UNINSTALL_KEY, KEY_READ | view_flag) {
            Ok(key) => key,
            Err(error) => {
                scan.warnings.push(format!(
                    "could not read {} {view_name} uninstall registry: {error}",
                    scope.as_str()
                ));
                continue;
            }
        };

        for key_name in key.enum_keys() {
            let key_name = match key_name {
                Ok(name) => name,
                Err(error) => {
                    scan.warnings.push(format!(
                        "could not enumerate {} {view_name} uninstall entry: {error}",
                        scope.as_str()
                    ));
                    continue;
                }
            };
            let entry = match key.open_subkey_with_flags(&key_name, KEY_READ | view_flag) {
                Ok(entry) => entry,
                Err(error) => {
                    scan.warnings.push(format!(
                        "could not open uninstall entry {key_name}: {error}"
                    ));
                    continue;
                }
            };
            let Some(name) = string_value(&entry, "DisplayName") else {
                continue;
            };

            let release_type = string_value(&entry, "ReleaseType");
            let update_or_hotfix = release_type.as_deref().is_some_and(|kind| {
                let kind = kind.to_ascii_lowercase();
                kind.contains("update") || kind.contains("hotfix") || kind.contains("security")
            }) || string_value(&entry, "ParentKeyName").is_some();
            let id = format!(
                "{}:{}:{}",
                match scope {
                    ProgramScope::CurrentUser => "user",
                    ProgramScope::AllUsers => "machine",
                },
                view_name,
                key_name
            );
            scan.programs.push(InstalledProgram {
                id,
                registry_key: key_name,
                name,
                version: string_value(&entry, "DisplayVersion"),
                publisher: string_value(&entry, "Publisher"),
                install_location: string_value(&entry, "InstallLocation").map(expand_environment),
                install_date: string_value(&entry, "InstallDate"),
                display_icon: string_value(&entry, "DisplayIcon").map(expand_environment),
                comments: string_value(&entry, "Comments"),
                website: string_value(&entry, "URLInfoAbout"),
                estimated_size_bytes: dword_value(&entry, "EstimatedSize")
                    .map(|kb| u64::from(kb) * 1024),
                scope,
                registry_view: view_name.to_string(),
                uninstall_command: string_value(&entry, "UninstallString"),
                quiet_uninstall_command: string_value(&entry, "QuietUninstallString"),
                system_component: dword_value(&entry, "SystemComponent") == Some(1),
                update_or_hotfix,
                windows_installer: dword_value(&entry, "WindowsInstaller") == Some(1),
                no_remove: dword_value(&entry, "NoRemove") == Some(1),
                parent_key_name: string_value(&entry, "ParentKeyName"),
            });
        }
    }

    // A handful of installers register the exact same entry into both views.
    // Keep relationships stable while removing only byte-for-byte identities.
    scan.programs.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.id.cmp(&b.id))
    });
    scan.programs.dedup_by(|a, b| {
        a.name.eq_ignore_ascii_case(&b.name)
            && a.version == b.version
            && normalized_optional_path(&a.install_location)
                == normalized_optional_path(&b.install_location)
            && a.publisher == b.publisher
            && a.scope == b.scope
    });
    scan
}

/// Returns only relationships explicitly present in uninstall metadata.
pub fn program_relationships(programs: &[InstalledProgram]) -> Vec<ProgramRelationship> {
    let mut by_key: HashMap<String, Vec<&InstalledProgram>> = HashMap::new();
    for program in programs {
        by_key
            .entry(program.registry_key.to_ascii_lowercase())
            .or_default()
            .push(program);
    }

    let mut relationships = Vec::new();
    for dependent in programs {
        let Some(parent_key) = dependent.parent_key_name.as_deref() else {
            continue;
        };
        let Some(candidates) = by_key.get(&parent_key.to_ascii_lowercase()) else {
            continue;
        };
        let parent = candidates
            .iter()
            .copied()
            .find(|candidate| candidate.scope == dependent.scope)
            .unwrap_or(candidates[0]);
        relationships.push(ProgramRelationship {
            parent_id: parent.id.clone(),
            dependent_id: dependent.id.clone(),
            source: "ParentKeyName".to_string(),
        });
    }
    relationships
}

/// Associates live processes with installed programs using executable paths
/// and parent chains. No match is made from the image filename alone.
pub fn attribute_processes(
    programs: &[InstalledProgram],
    processes: &[ProcessSample],
) -> ProgramAttribution {
    // Normalize registry paths once, not once per process/program pair. A
    // busy workstation can have 1,000+ processes and 500+ uninstall entries;
    // allocating lowercase strings in that inner product would make the
    // attribution pass more expensive than the sampling it explains.
    let rules = program_match_rules(programs);
    let direct: HashMap<u32, usize> = processes
        .iter()
        .filter_map(|process| {
            process
                .executable_path
                .as_deref()
                .and_then(|path| match_program_rules(&rules, path))
                .map(|program| (process.pid, program))
        })
        .collect();
    let parents: HashMap<u32, Option<u32>> = processes.iter().map(|p| (p.pid, p.ppid)).collect();

    let mut links = Vec::with_capacity(processes.len());
    let mut activities: Vec<ProgramActivity> = programs
        .iter()
        .map(|program| ProgramActivity {
            program_id: program.id.clone(),
            ..ProgramActivity::default()
        })
        .collect();

    for process in processes {
        let direct_program = direct.get(&process.pid).copied();
        let launcher_program = nearest_program_ancestor(process.ppid, &parents, &direct);
        if let Some(program) = direct_program {
            activities[program].direct_pids.push(process.pid);
        }
        if let Some(program) = launcher_program {
            activities[program].launched_pids.push(process.pid);
        }
        links.push(ProcessProgramLink {
            pid: process.pid,
            direct_program_id: direct_program.map(|i| programs[i].id.clone()),
            launcher_program_id: launcher_program.map(|i| programs[i].id.clone()),
        });
    }

    let by_pid: HashMap<u32, &ProcessSample> = processes.iter().map(|p| (p.pid, p)).collect();
    for activity in &mut activities {
        for pid in activity.all_pids() {
            let Some(process) = by_pid.get(&pid) else {
                continue;
            };
            activity.cpu_percent += process.cpu_percent;
            activity.gpu_percent += process.gpu_percent;
            activity.memory_bytes += process.mem_bytes.unwrap_or(0);
        }
        activity.direct_pids.sort_unstable();
        activity.launched_pids.sort_unstable();
        activity.launched_pids.dedup();
    }

    ProgramAttribution { links, activities }
}

/// Evidence-based attention notes for a live process. An empty result means
/// only “no obvious path/parent indicator,” never “verified safe.”
pub fn process_attention_reasons(process: &ProcessSample) -> Vec<String> {
    let Some(path) = process.executable_path.as_deref() else {
        return vec!["executable path is unavailable, so identity cannot be verified".into()];
    };
    let normalized = normalize_path(path);
    let mut reasons = Vec::new();
    if is_transient_path(&normalized) {
        reasons.push("executable is running from a temporary or Downloads directory".into());
    }
    if normalized.starts_with(r"\\") {
        reasons.push("executable is running from a network path".into());
    }

    let image = process.name.to_ascii_lowercase();
    let system_names = [
        "csrss.exe",
        "lsass.exe",
        "services.exe",
        "smss.exe",
        "svchost.exe",
        "wininit.exe",
        "winlogon.exe",
    ];
    if system_names.contains(&image.as_str()) {
        let windir =
            normalize_path(&std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into()));
        if !path_is_within(&normalized, &windir) {
            reasons.push(format!(
                "uses the Windows system name {image} but is outside the Windows directory"
            ));
        }
    }
    reasons
}

fn nearest_program_ancestor(
    mut pid: Option<u32>,
    parents: &HashMap<u32, Option<u32>>,
    direct: &HashMap<u32, usize>,
) -> Option<usize> {
    let mut seen = HashSet::new();
    for _ in 0..128 {
        let current = pid?;
        if !seen.insert(current) {
            return None;
        }
        if let Some(program) = direct.get(&current) {
            return Some(*program);
        }
        pid = parents.get(&current).copied().flatten();
    }
    None
}

struct ProgramMatchRule {
    index: usize,
    location: Option<String>,
    icon: Option<String>,
}

fn program_match_rules(programs: &[InstalledProgram]) -> Vec<ProgramMatchRule> {
    let locations: Vec<_> = programs
        .iter()
        .map(|program| {
            normalized_optional_path(&program.install_location)
                .filter(|location| !is_generic_install_location(location))
        })
        .collect();
    let icons: Vec<_> = programs
        .iter()
        .map(|program| {
            program
                .display_icon
                .as_deref()
                .and_then(display_icon_path)
                .map(|path| normalize_path(&path))
        })
        .collect();
    let mut location_counts: HashMap<&str, usize> = HashMap::new();
    for location in locations.iter().flatten() {
        *location_counts.entry(location).or_default() += 1;
    }
    let mut icon_counts: HashMap<&str, usize> = HashMap::new();
    for icon in icons.iter().flatten() {
        *icon_counts.entry(icon).or_default() += 1;
    }

    programs
        .iter()
        .enumerate()
        .filter_map(|(index, _program)| {
            // A shared location (Office components are a common example)
            // cannot identify which uninstall entry owns an executable.
            // Keep exact DisplayIcon matches, but drop ambiguous directory
            // rules rather than assigning activity to whichever entry sorts
            // first.
            let location = locations[index]
                .clone()
                .filter(|location| location_counts.get(location.as_str()) == Some(&1));
            let icon = icons[index]
                .clone()
                .filter(|icon| icon_counts.get(icon.as_str()) == Some(&1));
            (location.is_some() || icon.is_some()).then_some(ProgramMatchRule {
                index,
                location,
                icon,
            })
        })
        .collect()
}

fn is_generic_install_location(location: &str) -> bool {
    if location.len() <= 3 {
        return true;
    }
    [
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
        "WINDIR",
        "SystemRoot",
    ]
    .iter()
    .filter_map(|variable| std::env::var(variable).ok())
    .map(|path| normalize_path(&path))
    .any(|generic| location == generic)
}

fn match_program_rules(rules: &[ProgramMatchRule], executable_path: &str) -> Option<usize> {
    let path = normalize_path(executable_path);
    let mut best: Option<(usize, usize)> = None;
    for rule in rules {
        let mut score = 0usize;
        if rule.icon.as_deref() == Some(path.as_str()) {
            score = usize::MAX;
        }
        if score != usize::MAX
            && let Some(location) = rule.location.as_deref()
            && path_is_within(&path, location)
        {
            score = location.len();
        }
        if score > 0 && best.is_none_or(|(_, old_score)| score > old_score) {
            best = Some((rule.index, score));
        }
    }
    best.map(|(index, _)| index)
}

#[cfg(test)]
fn match_program_index(programs: &[InstalledProgram], executable_path: &str) -> Option<usize> {
    match_program_rules(&program_match_rules(programs), executable_path)
}

fn path_is_within(path: &str, directory: &str) -> bool {
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|rest| rest.starts_with('\\'))
}

fn is_transient_path(path: &str) -> bool {
    path.contains(r"\temp\")
        || path.ends_with(r"\temp")
        || path.contains(r"\downloads\")
        || path.ends_with(r"\downloads")
}

fn normalize_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn normalized_optional_path(path: &Option<String>) -> Option<String> {
    path.as_deref()
        .map(normalize_path)
        .filter(|p| !p.is_empty())
}

fn display_icon_path(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    let path = value
        .rsplit_once(',')
        .filter(|(_, index)| index.trim().parse::<i32>().is_ok())
        .map_or(value, |(path, _)| path);
    (!path.trim().is_empty()).then(|| path.trim().to_string())
}

fn string_value(key: &RegKey, name: &str) -> Option<String> {
    key.get_value::<String, _>(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn dword_value(key: &RegKey, name: &str) -> Option<u32> {
    key.get_value::<u32, _>(name).ok()
}

fn expand_environment(value: String) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value.as_str();
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            output.push_str(&rest[start..]);
            return output;
        };
        let variable = &after[..end];
        match std::env::var(variable) {
            Ok(replacement) => output.push_str(&replacement),
            Err(_) => {
                output.push('%');
                output.push_str(variable);
                output.push('%');
            }
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GpuSource;

    fn program(id: &str, name: &str, location: &str) -> InstalledProgram {
        InstalledProgram {
            id: id.into(),
            registry_key: id.into(),
            name: name.into(),
            version: None,
            publisher: Some("Publisher".into()),
            install_location: Some(location.into()),
            install_date: None,
            display_icon: None,
            comments: None,
            website: None,
            estimated_size_bytes: None,
            scope: ProgramScope::AllUsers,
            registry_view: "64-bit".into(),
            uninstall_command: Some("uninstall.exe".into()),
            quiet_uninstall_command: None,
            system_component: false,
            update_or_hotfix: false,
            windows_installer: false,
            no_remove: false,
            parent_key_name: None,
        }
    }

    fn process(pid: u32, ppid: Option<u32>, name: &str, path: &str, cpu: f32) -> ProcessSample {
        ProcessSample {
            pid,
            ppid,
            name: name.into(),
            cpu_percent: cpu,
            gpu_percent: 0.0,
            gpu_source: GpuSource::Unavailable,
            user: None,
            command_line: None,
            executable_path: Some(path.into()),
            handle_count: None,
            mem_bytes: Some(10),
        }
    }

    #[test]
    fn longest_install_location_wins() {
        let programs = [
            program("suite", "Suite", r"C:\Apps\Suite"),
            program("tool", "Tool", r"C:\Apps\Suite\Tool"),
        ];
        assert_eq!(
            match_program_index(&programs, r"C:\Apps\Suite\Tool\tool.exe"),
            Some(1)
        );
    }

    #[test]
    fn shared_install_locations_are_not_arbitrarily_attributed() {
        let programs = [
            program("suite-a", "Suite A", r"C:\Apps\Shared"),
            program("suite-b", "Suite B", r"C:\Apps\Shared"),
        ];
        assert_eq!(
            match_program_index(&programs, r"C:\Apps\Shared\worker.exe"),
            None
        );
    }

    #[test]
    fn generic_install_roots_do_not_claim_every_process_below_them() {
        let Some(program_files) = std::env::var("ProgramFiles").ok() else {
            return;
        };
        let programs = [program("generic", "Generic", &program_files)];
        assert_eq!(
            match_program_index(&programs, &format!(r"{program_files}\Unrelated\worker.exe")),
            None
        );
    }

    #[test]
    fn child_is_attributed_to_the_program_that_launched_it() {
        let programs = [program("warp", "Warp", r"C:\Apps\Warp")];
        let processes = [
            process(10, None, "warp.exe", r"C:\Apps\Warp\warp.exe", 2.0),
            process(
                11,
                Some(10),
                "find.exe",
                r"C:\Windows\System32\find.exe",
                7.0,
            ),
        ];
        let attribution = attribute_processes(&programs, &processes);
        let activity = &attribution.activities[0];
        assert_eq!(activity.direct_pids, [10]);
        assert_eq!(activity.launched_pids, [11]);
        assert_eq!(activity.cpu_percent, 9.0);
        assert_eq!(
            attribution.links[1].launcher_program_id.as_deref(),
            Some("warp")
        );
    }

    #[test]
    fn parent_key_relationships_are_not_guessed() {
        let parent = program("parent-id", "Main App", r"C:\App");
        let mut child = program("child-id", "Main App Update", r"C:\App");
        child.registry_key = "update-key".into();
        child.parent_key_name = Some(parent.registry_key.clone());
        let relationships = program_relationships(&[parent, child]);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].parent_id, "parent-id");
        assert_eq!(relationships[0].dependent_id, "child-id");
    }

    #[test]
    fn system_name_outside_windows_is_flagged() {
        let suspect = process(
            10,
            None,
            "svchost.exe",
            r"C:\Users\me\Downloads\svchost.exe",
            0.0,
        );
        let reasons = process_attention_reasons(&suspect);
        assert!(reasons.iter().any(|reason| reason.contains("Downloads")));
        assert!(reasons.iter().any(|reason| reason.contains("system name")));
    }

    #[test]
    fn display_icon_parser_drops_resource_index() {
        assert_eq!(
            display_icon_path(r#""C:\Program Files\App\app.exe",0"#).as_deref(),
            Some(r"C:\Program Files\App\app.exe")
        );
        assert_eq!(
            display_icon_path(r"C:\App\app.exe,-1").as_deref(),
            Some(r"C:\App\app.exe")
        );
    }
}
