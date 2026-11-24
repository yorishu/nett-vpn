#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(feature = "ui-preview", allow(dead_code))]

mod crt;
#[cfg(feature = "ui-preview")]
mod preview;
mod profiles;
mod settings;
mod split;
mod storage;
mod tray;

use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};
use std::os::windows::process::CommandExt;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

const BG: Color32 = Color32::from_rgb(20, 29, 24);
const PANEL: Color32 = Color32::from_rgb(35, 49, 39);
const SCREEN: Color32 = Color32::from_rgb(16, 27, 20);
const LIME: Color32 = Color32::from_rgb(156, 255, 68);
const DIM: Color32 = Color32::from_rgb(128, 172, 104);

#[derive(Clone, Copy, PartialEq)]
enum Protocol {
    WireGuard,
    AmneziaWg,
}

enum Completion {
    Cancelled,
    Toggled(bool),
    DisplaySaved(bool, bool),
    Library(
        profiles::Library,
        Option<(PathBuf, Protocol, bool)>,
        Option<String>,
    ),
    AppPicked(Option<PathBuf>),
}

struct NettVpn {
    library: profiles::Library,
    settings: Option<settings::Settings>,
    display_started: std::time::Instant,
    reduced_motion: bool,
    config: Option<PathBuf>,
    protocol: Option<Protocol>,
    connected: bool,
    message: String,
    pending: Option<Receiver<Result<Completion, String>>>,
    tray: Option<tray::Tray>,
    quit_requested: bool,
    allow_close: bool,
    status: Option<Receiver<bool>>,
    last_status: std::time::Instant,
}

impl Default for NettVpn {
    fn default() -> Self {
        Self {
            library: Default::default(),
            settings: None,
            display_started: std::time::Instant::now(),
            reduced_motion: crt::reduced_motion(),
            tray: None,
            quit_requested: false,
            allow_close: false,
            status: None,
            last_status: std::time::Instant::now(),
            pending: None,
            config: None,
            protocol: None,
            connected: false,
            message: "IMPORT A .CONF CONFIG TO BEGIN".into(),
        }
    }
}

impl NettVpn {
    fn start(
        &mut self,
        ctx: &egui::Context,
        message: &str,
        work: impl FnOnce() -> Result<Completion, String> + Send + 'static,
    ) {
        if self.pending.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        self.message = message.into();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = work();
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }

    fn poll(&mut self) {
        let Some(rx) = &self.pending else { return };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("OPERATION FAILED - WORKER STOPPED".into()),
        };
        self.pending = None;
        match result {
            Ok(Completion::DisplaySaved(effects, motion)) => {
                self.library.effects = effects;
                self.library.motion = motion;
                if let Some(settings) = &mut self.settings {
                    settings.accept_display(effects, motion);
                }
                self.message = "DISPLAY SETTINGS SAVED".into();
            }
            Ok(Completion::Library(library, active, warning)) => {
                self.message = warning.unwrap_or_else(|| {
                    library
                        .selected()
                        .map(|p| format!("PROFILE LOADED - {}", p.name))
                        .unwrap_or_else(|| "IMPORT A .CONF CONFIG TO BEGIN".into())
                });
                self.config = active.as_ref().map(|a| a.0.clone());
                self.protocol = active.as_ref().map(|a| a.1);
                self.connected = active.is_some_and(|a| a.2);
                if let Some(settings) = &mut self.settings {
                    settings.accept_saved(library.clone());
                }
                self.library = library;
            }
            Ok(Completion::AppPicked(path)) => {
                if let (Some(settings), Some(path)) = (&mut self.settings, path) {
                    settings.add_app(path.to_string_lossy().into_owned());
                }
                self.message = "APPLICATION SELECTION COMPLETE".into();
            }
            Ok(Completion::Cancelled) => self.message = "IMPORT CANCELLED".into(),
            Ok(Completion::Toggled(connected)) => {
                self.connected = connected;
                if self.quit_requested && !connected {
                    self.allow_close = true;
                }
                self.message = if connected {
                    "TUNNEL SERVICE STARTED"
                } else {
                    "TUNNEL SERVICE STOPPED"
                }
                .into();
            }
            Err(error) => {
                self.message = error;
                self.quit_requested = false;
            }
        }
    }

    fn import(&mut self, ctx: &egui::Context) {
        if self.connected {
            return;
        }
        let mut library = self
            .settings
            .as_ref()
            .map(|s| s.draft.clone())
            .unwrap_or_else(|| self.library.clone());
        self.start(ctx, "IMPORTING CONFIG...", move || {
            ensure_editable(&library)?;
            let Some(path) = rfd::FileDialog::new()
                .add_filter("VPN config", &["conf"])
                .pick_file()
            else {
                return Ok(Completion::Cancelled);
            };
            library.import(&path)?;
            library.save()?;
            library_completion(library)
        });
    }

    fn toggle(&mut self, ctx: &egui::Context) {
        let (Some(path), Some(protocol)) = (self.config.clone(), self.protocol) else {
            return;
        };
        let connected = self.connected;
        let profile = self.library.selected().cloned();
        self.start(
            ctx,
            if connected {
                "DISCONNECTING..."
            } else {
                "CONNECTING..."
            },
            move || {
                if connected && split::running(&path) {
                    split::stop(&path)?;
                    return Ok(Completion::Toggled(false));
                }
                if !connected
                    && let Some(profile) = profile
                    && profile.split()
                {
                    split::start(&profile)?;
                    return Ok(Completion::Toggled(true));
                }
                let engine = engine_path(protocol).ok_or_else(|| match protocol {
                    Protocol::WireGuard => "WIREGUARD FOR WINDOWS NOT FOUND".to_string(),
                    Protocol::AmneziaWg => "AMNEZIAWG FOR WINDOWS NOT FOUND".to_string(),
                })?;
                let (verb, arg) = if connected {
                    ("/uninstalltunnelservice", tunnel_name(&path))
                } else {
                    ("/installtunnelservice", path.to_string_lossy().into_owned())
                };
                elevate_engine(&engine, verb, &arg)?;
                let running = tunnel_running(protocol, &path);
                if running == connected {
                    return Err("TUNNEL SERVICE DID NOT CHANGE STATE".into());
                }
                Ok(Completion::Toggled(running))
            },
        );
    }
}

fn library_completion(mut library: profiles::Library) -> Result<Completion, String> {
    let mut active = None;
    for profile in &library.profiles {
        let path = profile.path()?;
        if connection_running(profile.protocol(), &path) {
            if active.is_some() {
                return Err("MULTIPLE ACTIVE PROFILES - STOP EXTRA TUNNELS FIRST".into());
            }
            active = Some(profile.id.clone());
        }
    }
    if let Some(active) = active {
        library.selected = Some(active);
    }
    let selection = if let Some(profile) = library.selected() {
        let path = profile.stage()?;
        let protocol = profile.protocol();
        let connected = connection_running(protocol, &path);
        Some((path, protocol, connected))
    } else {
        None
    };
    Ok(Completion::Library(library, selection, None))
}

fn connection_running(protocol: Protocol, path: &Path) -> bool {
    split::running(path) || tunnel_running(protocol, path)
}

fn ensure_editable(library: &profiles::Library) -> Result<(), String> {
    for profile in &library.profiles {
        if connection_running(profile.protocol(), &profile.path()?) {
            return Err("DISCONNECT BEFORE EDITING PROFILES OR RULES".into());
        }
    }
    Ok(())
}

fn detect_config(path: &Path) -> Result<Protocol, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("CANNOT READ CONFIG - {e}"))?
        .len();
    if size > 1024 * 1024 {
        return Err("CONFIG TOO LARGE - MAX 1 MB".into());
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("CANNOT READ CONFIG - {e}"))?;
    let mut section = "";
    let mut interface = false;
    let mut peer = false;
    let mut private_key = false;
    let mut public_key = false;
    let mut endpoint = false;
    let mut awg = false;
    // shortcut: checks protocol markers only; the official tunnel engine validates the full config.
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if line.starts_with('[') {
            section = if line.eq_ignore_ascii_case("[Interface]") {
                "interface"
            } else if line.eq_ignore_ascii_case("[Peer]") {
                "peer"
            } else {
                "other"
            };
            interface |= section == "interface";
            peer |= section == "peer";
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if section == "interface" && key.eq_ignore_ascii_case("PrivateKey") && !value.is_empty()
            {
                private_key = true;
            }
            if section == "peer" && key.eq_ignore_ascii_case("PublicKey") && !value.is_empty() {
                public_key = true;
            }
            if section == "peer" && key.eq_ignore_ascii_case("Endpoint") && !value.is_empty() {
                endpoint = true;
            }
            if section == "interface"
                && [
                    "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                ]
                .iter()
                .any(|k| key.eq_ignore_ascii_case(k))
            {
                awg = true;
            }
        }
    }
    if !(interface && peer && private_key && public_key && endpoint) {
        return Err("INVALID CONFIG - CHECK INTERFACE, PEER, KEYS AND ENDPOINT".into());
    }
    Ok(if awg {
        Protocol::AmneziaWg
    } else {
        Protocol::WireGuard
    })
}

fn engine_path(protocol: Protocol) -> Option<PathBuf> {
    let pf = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    let portable = std::env::current_exe().ok()?.parent()?.join("engines");
    find_engine(protocol, &pf, &portable)
}

fn find_engine(protocol: Protocol, installed: &Path, portable: &Path) -> Option<PathBuf> {
    let candidates: &[&str] = match protocol {
        Protocol::WireGuard => &[r"WireGuard\wireguard.exe"],
        Protocol::AmneziaWg => &[r"AmneziaWG\amneziawg.exe", r"AmneziaWG\wireguard.exe"],
    };
    [portable, installed]
        .into_iter()
        .flat_map(|root| candidates.iter().map(move |p| root.join(p)))
        .find(|p| p.is_file())
}

fn tunnel_name(path: &Path) -> String {
    path.file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

fn tunnel_running(protocol: Protocol, path: &Path) -> bool {
    let prefix = match protocol {
        Protocol::WireGuard => "WireGuardTunnel$",
        Protocol::AmneziaWg => "AmneziaWGTunnel$",
    };
    let Ok(output) = Command::new("sc.exe")
        .args(["query", &format!("{prefix}{}", tunnel_name(path))])
        .creation_flags(0x08000000)
        .output()
    else {
        return false;
    };
    output.status.success() && String::from_utf8_lossy(&output.stdout).contains(": 4")
}

fn elevate_engine(engine: &Path, verb: &str, argument: &str) -> Result<(), String> {
    let script = "$ErrorActionPreference = 'Stop'; $arg = $env:NETT_VERB + ' \"' + $env:NETT_ARGUMENT + '\"'; $p = Start-Process -FilePath $env:NETT_ENGINE -ArgumentList $arg -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode";
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("NETT_ENGINE", engine)
        .env("NETT_VERB", verb)
        .env("NETT_ARGUMENT", argument)
        .creation_flags(0x08000000)
        .status()
        .map_err(|e| format!("CANNOT START VPN ENGINE - {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ENGINE FAILED - EXIT {}",
            status.code().unwrap_or(-1)
        ))
    }
}

impl eframe::App for NettVpn {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0.0; 4]
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.render_frame(ctx);
    }
}

impl NettVpn {
    fn render_frame(&mut self, ctx: &egui::Context) {
        ctx.style_mut(|style| style.interaction.selectable_labels = false);
        self.poll();
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        if let Some(tray) = &mut self.tray {
            if tray.quit.try_recv().is_ok() {
                self.quit_requested = true;
            }
            if let Err(error) = tray.update(self.connected) {
                self.message = error;
            }
        }
        if self.quit_requested && self.pending.is_none() {
            if self.allow_close || self.config.is_none() {
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else if let (Some(path), Some(protocol)) = (self.config.clone(), self.protocol) {
                self.start(ctx, "STOPPING TUNNEL...", move || {
                    split::stop(&path)?;
                    if tunnel_running(protocol, &path) {
                        let engine = engine_path(protocol).ok_or("VPN ENGINE NOT FOUND")?;
                        elevate_engine(&engine, "/uninstalltunnelservice", &tunnel_name(&path))?;
                        if tunnel_running(protocol, &path) {
                            return Err("TUNNEL STILL RUNNING - EXIT CANCELLED".into());
                        }
                    }
                    Ok(Completion::Toggled(false))
                });
            }
        }
        if self.pending.is_none() && !self.quit_requested {
            if let Some(rx) = &self.status {
                if let Ok(connected) = rx.try_recv() {
                    self.connected = connected;
                    self.status = None;
                }
            }
            if self.status.is_none() && self.last_status.elapsed() >= Duration::from_secs(3) {
                self.last_status = std::time::Instant::now();
                if let (Some(path), Some(protocol)) = (self.config.clone(), self.protocol) {
                    let (tx, rx) = mpsc::channel();
                    self.status = Some(rx);
                    let ctx = ctx.clone();
                    std::thread::spawn(move || {
                        let _ = tx.send(connection_running(protocol, &path));
                        ctx.request_repaint();
                    });
                }
            }
        } else {
            self.status = None;
        }
        let dots = [".", "..", "..."][(ctx.input(|i| i.time) * 2.0) as usize % 3];
        let title = if self.pending.is_some() {
            format!(
                "nett - {}{dots}",
                self.message.trim_end_matches('.').to_lowercase()
            )
        } else if self.connected {
            "nett - wired".into()
        } else {
            format!("nett - waiting{dots}")
        };
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.clone()));
        ctx.request_repaint_after(Duration::from_millis(500));
        if ctx.input(|i| i.key_pressed(egui::Key::F8)) {
            let display = self
                .settings
                .as_mut()
                .map(|s| &mut s.draft)
                .unwrap_or(&mut self.library);
            display.effects = !display.effects;
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(18.0)
                    .corner_radius(egui::CornerRadius::same(22)),
            )
            .show(ctx, |ui| {
                ui.set_min_size(Vec2::new(590.0, 365.0));
                let (bar, _) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 32.0),
                    egui::Sense::hover(),
                );
                let quit_rect = egui::Rect::from_min_size(
                    egui::pos2(bar.right() - 64.0, bar.top()),
                    Vec2::new(64.0, 32.0),
                );
                let hide_rect = quit_rect.translate(Vec2::new(-72.0, 0.0));
                let drag_rect = egui::Rect::from_min_max(
                    bar.min,
                    egui::pos2(hide_rect.left() - 8.0, bar.bottom()),
                );
                let drag = ui.interact(
                    drag_rect,
                    ui.id().with("window-drag"),
                    egui::Sense::click_and_drag(),
                );
                if drag.is_pointer_button_down_on() && ctx.input(|i| i.pointer.primary_pressed()) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
                }
                ui.painter().text(
                    bar.left_center(),
                    egui::Align2::LEFT_CENTER,
                    "[k]",
                    FontId::monospace(16.0),
                    LIME,
                );
                ui.painter().text(
                    bar.center(),
                    egui::Align2::CENTER_CENTER,
                    &title,
                    FontId::monospace(13.0),
                    LIME,
                );
                if ui
                    .put(
                        hide_rect,
                        egui::Button::new(RichText::new("HIDE").monospace()),
                    )
                    .clicked()
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
                ui.scope(|ui| {
                    if ui
                        .put(
                            quit_rect,
                            egui::Button::new(RichText::new("CLOSE").monospace()),
                        )
                        .clicked()
                    {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    }
                });
                ui.add_space(8.0);
                if self.settings.is_some() {
                    let action = self.settings.as_mut().unwrap().show(
                        ui,
                        self.connected,
                        self.pending.is_some(),
                    );
                    match action {
                        Some(settings::Action::SaveDisplay(effects, motion)) => {
                            let mut library = self.library.clone();
                            library.effects = effects;
                            library.motion = motion;
                            self.start(ctx, "SAVING DISPLAY...", move || {
                                library.save()?;
                                Ok(Completion::DisplaySaved(effects, motion))
                            });
                        }
                        Some(settings::Action::Close) => {
                            self.settings = None;
                            self.display_started = std::time::Instant::now();
                        }
                        Some(settings::Action::Import) => self.import(ctx),
                        Some(settings::Action::PickApp) => {
                            self.start(ctx, "SELECTING APPLICATION...", || {
                                Ok(Completion::AppPicked(
                                    rfd::FileDialog::new()
                                        .add_filter("Windows application", &["exe"])
                                        .pick_file(),
                                ))
                            })
                        }
                        Some(settings::Action::Save(library)) => {
                            let previous = self.library.clone();
                            self.start(ctx, "SAVING SETTINGS...", move || {
                                ensure_editable(&previous)?;
                                library.save()?;
                                let mut warning = None;
                                for removed in previous.profiles.iter().filter(|old| {
                                    !library.profiles.iter().any(|new| new.id == old.id)
                                }) {
                                    for ext in
                                        ["conf", "split.json", "split.log", "ready.json", "stop"]
                                    {
                                        match std::fs::remove_file(
                                            removed.path()?.with_extension(ext),
                                        ) {
                                            Ok(()) => (),
                                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                                ()
                                            }
                                            Err(e) => {
                                                warning = Some(format!(
                                                    "PROFILE DELETED BUT FILE CLEANUP FAILED: {e}"
                                                ))
                                            }
                                        }
                                    }
                                }
                                let mut result = library_completion(library)?;
                                if let Completion::Library(_, _, notice) = &mut result {
                                    *notice =
                                        Some(warning.unwrap_or_else(|| "SETTINGS SAVED".into()));
                                }
                                Ok(result)
                            });
                        }
                        None => (),
                    }
                    ui.add_space(8.0);
                    ui.label(RichText::new(&self.message).monospace().color(DIM));
                    return;
                }
                egui::Frame::new()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0_f32, DIM))
                    .inner_margin(egui::Margin::symmetric(16, 12))
                    .corner_radius(egui::CornerRadius::same(18))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("nett vpn")
                                    .font(FontId::monospace(16.0))
                                    .color(LIME)
                                    .strong(),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new("WINDOWS - BUILD 0.2.4")
                                            .font(FontId::monospace(11.0))
                                            .color(DIM),
                                    );
                                },
                            );
                        });
                        ui.add_space(10.0);
                        egui::Frame::new()
                            .fill(SCREEN)
                            .stroke(Stroke::new(1.0_f32, DIM))
                            .inner_margin(egui::Margin::symmetric(18, 14))
                            .corner_radius(egui::CornerRadius::same(12))
                            .show(ui, |ui| {
                                ui.set_min_height(250.0);
                                ui.set_min_width(ui.available_width());
                                ui.label(
                                    RichText::new(if self.connected {
                                        "[+] LINK ACTIVE"
                                    } else {
                                        "[-] LINK OFFLINE"
                                    })
                                    .font(FontId::monospace(13.0))
                                    .color(if self.connected { LIME } else { DIM })
                                    .strong(),
                                );
                                ui.add_space(6.0);
                                ui.vertical(|ui| {
                                    if ui
                                        .add_sized(
                                            [120.0, 32.0],
                                            egui::Button::new(
                                                RichText::new("SETTINGS").monospace().color(LIME),
                                            )
                                            .fill(PANEL),
                                        )
                                        .clicked()
                                    {
                                        self.settings =
                                            Some(settings::Settings::new(self.library.clone()));
                                        self.display_started = std::time::Instant::now();
                                    }
                                    if ui
                                        .add_enabled_ui(
                                            self.pending.is_none() && !self.connected,
                                            |ui| {
                                                ui.add_sized(
                                                    [120.0, 32.0],
                                                    egui::Button::new(
                                                        RichText::new("IMPORT .CONF")
                                                            .monospace()
                                                            .color(LIME),
                                                    )
                                                    .fill(PANEL),
                                                )
                                            },
                                        )
                                        .inner
                                        .clicked()
                                    {
                                        self.import(ctx);
                                    }
                                });
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("+--------------------------------------------+")
                                        .monospace()
                                        .color(DIM),
                                );
                                ui.label(
                                    RichText::new("|    N E T T   T U N N E L   S Y S T E M     |")
                                        .monospace()
                                        .color(LIME)
                                        .strong(),
                                );
                                ui.label(
                                    RichText::new("+--------------------------------------------+")
                                        .monospace()
                                        .color(DIM),
                                );
                                ui.add_space(8.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("PROTOCOL   ").monospace().color(DIM));
                                    ui.label(
                                        RichText::new(
                                            self.protocol
                                                .map(|p| match p {
                                                    Protocol::WireGuard => "WIREGUARD",
                                                    Protocol::AmneziaWg => "AMNEZIAWG",
                                                })
                                                .unwrap_or("NONE"),
                                        )
                                        .monospace()
                                        .color(LIME),
                                    );
                                });
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("PROFILE    ").monospace().color(DIM));
                                    ui.label(
                                        RichText::new(
                                            self.library
                                                .selected()
                                                .map(|p| p.name.clone())
                                                .unwrap_or_else(|| "NO PROFILE SELECTED".into()),
                                        )
                                        .monospace()
                                        .color(LIME),
                                    );
                                });
                                ui.add_space(14.0);
                                ui.label(RichText::new(&self.message).monospace().color(
                                    if self.message.contains("FAILED")
                                        || self.message.contains("NOT FOUND")
                                        || self.message.starts_with("INVALID")
                                    {
                                        Color32::LIGHT_RED
                                    } else {
                                        DIM
                                    },
                                ));
                                ui.add_space(18.0);
                                let label = if self.pending.is_some() {
                                    "WORKING..."
                                } else if self.connected {
                                    "DISCONNECT"
                                } else {
                                    "CONNECT"
                                };
                                let button = egui::Button::new(
                                    RichText::new(format!("  {label}  "))
                                        .font(FontId::monospace(16.0))
                                        .strong()
                                        .color(SCREEN),
                                )
                                .fill(LIME)
                                .corner_radius(egui::CornerRadius::same(6));
                                if ui
                                    .add_enabled(
                                        self.config.is_some() && self.pending.is_none(),
                                        button,
                                    )
                                    .clicked()
                                {
                                    self.toggle(ctx);
                                }
                                ui.add_space(16.0);
                                ui.label(
                                    RichText::new(
                                        if self.library.selected().is_some_and(|p| p.split()) {
                                            "ENGINE: NETT SPLIT CORE - UAC REQUIRED"
                                        } else {
                                            "ENGINE: WINDOWS TUNNEL SERVICE - UAC REQUIRED"
                                        },
                                    )
                                    .monospace()
                                    .size(10.0)
                                    .color(DIM),
                                );
                            });
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("SECURE TUNNEL CLIENT")
                                    .monospace()
                                    .size(9.0)
                                    .color(DIM),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new("NETT  /  01")
                                            .monospace()
                                            .size(9.0)
                                            .color(DIM),
                                    );
                                },
                            );
                        });
                    });
            });
        let display = self
            .settings
            .as_ref()
            .map(|s| &s.draft)
            .unwrap_or(&self.library);
        if display.effects {
            crt::paint(
                ctx,
                ctx.screen_rect(),
                self.display_started.elapsed().as_secs_f64(),
                display.motion && !self.reduced_motion,
            );
        }
    }
}

fn terminal_icon() -> egui::IconData {
    let glyph = [
        0b01000000, 0b01000000, 0b01001000, 0b01010000, 0b01100000, 0b01010000, 0b01001000,
        0b00000000,
    ];
    let mut rgba = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 {
        for x in 0..32 {
            let lit = glyph[y / 4] & (0x80 >> (x / 4)) != 0;
            rgba.extend_from_slice(&if lit {
                LIME.to_array()
            } else {
                SCREEN.to_array()
            });
        }
    }
    egui::IconData {
        rgba,
        width: 32,
        height: 32,
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([660.0, 490.0])
            .with_min_inner_size([620.0, 420.0])
            .with_title("nett - waiting.")
            .with_icon(terminal_icon())
            .with_decorations(false)
            .with_transparent(true)
            .with_resizable(false)
            .with_maximize_button(false)
            .with_fullscreen(false),
        ..Default::default()
    };
    eframe::run_native(
        "nett",
        options,
        Box::new(|cc| {
            let mut visuals = egui::Visuals::dark();
            visuals.override_text_color = Some(LIME);
            visuals.widgets.inactive.weak_bg_fill = PANEL;
            visuals.widgets.hovered.weak_bg_fill = SCREEN;
            visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, LIME);
            visuals.widgets.active.weak_bg_fill = PANEL;
            visuals.selection.bg_fill = Color32::from_rgb(48, 78, 34);
            visuals.selection.stroke = Stroke::new(1.0_f32, LIME);
            cc.egui_ctx.set_visuals(visuals);
            let mut style = (*cc.egui_ctx.style()).clone();
            style.override_text_style = Some(egui::TextStyle::Monospace);
            cc.egui_ctx.set_style(style);
            #[cfg(feature = "ui-preview")]
            {
                return Ok(Box::new(preview::app()));
            }
            #[cfg(not(feature = "ui-preview"))]
            {
                let mut app = NettVpn::default();
                app.tray = Some(tray::Tray::new(cc)?);
                app.start(&cc.egui_ctx, "LOADING PROFILES...", || {
                    library_completion(profiles::Library::load()?)
                });
                Ok(Box::new(app))
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn failed_operation_preserves_rules_and_unsaved_draft() {
        let mut app = super::NettVpn::default();
        app.library.profiles.push(super::profiles::Profile {
            id: "test".into(),
            name: "home".into(),
            config: "[Interface]\nJc=4\nDisableCookies=".into(),
            sites: super::profiles::Rules {
                enabled: true,
                mode: super::profiles::Mode::Direct,
                entries: vec!["example.com".into()],
            },
            apps: super::profiles::Rules {
                enabled: true,
                mode: super::profiles::Mode::Direct,
                entries: vec![r"C:\Apps\ShairportQt.exe".into()],
            },
        });
        app.library.selected = Some("test".into());
        let saved = app.library.clone();
        app.settings = Some(super::settings::Settings::new(saved.clone()));
        app.settings
            .as_mut()
            .unwrap()
            .draft
            .selected_mut()
            .unwrap()
            .sites
            .entries
            .push("192.168.10.0/24".into());
        let draft = app.settings.as_ref().unwrap().draft.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Err("ENGINE FAILED".into())).unwrap();
        app.pending = Some(rx);
        app.poll();
        assert!(app.library == saved);
        assert!(app.settings.as_ref().unwrap().draft == draft);
        assert!(!app.connected);
    }
    fn ui_frame(
        app: &mut super::NettVpn,
        ctx: &super::egui::Context,
        events: Vec<super::egui::Event>,
    ) -> super::egui::FullOutput {
        ctx.style_mut(|s| s.override_text_style = Some(super::egui::TextStyle::Monospace));
        ctx.run(
            super::egui::RawInput {
                screen_rect: Some(super::egui::Rect::from_min_size(
                    super::egui::Pos2::ZERO,
                    super::egui::vec2(660.0, 490.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| app.render_frame(ctx),
        )
    }

    fn text_rect(output: &super::egui::FullOutput, label: &str) -> super::egui::Rect {
        fn find(shape: &super::egui::Shape, label: &str) -> Option<super::egui::Rect> {
            match shape {
                super::egui::Shape::Text(text) if text.galley.job.text == label => {
                    Some(text.galley.rect.translate(text.pos.to_vec2()))
                }
                super::egui::Shape::Vec(shapes) => shapes.iter().find_map(|s| find(s, label)),
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|s| find(&s.shape, label))
            .unwrap_or_else(|| panic!("label not rendered: {label}"))
    }

    fn click(app: &mut super::NettVpn, ctx: &super::egui::Context, pos: super::egui::Pos2) {
        for pressed in [true, false] {
            ui_frame(
                app,
                ctx,
                vec![
                    super::egui::Event::PointerMoved(pos),
                    super::egui::Event::PointerButton {
                        pos,
                        button: super::egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
    }

    #[test]
    fn settings_navigation_is_clickable_and_fits_fixed_window() {
        let ctx = super::egui::Context::default();
        let mut app = super::NettVpn::default();
        let output = ui_frame(&mut app, &ctx, vec![]);
        let settings = text_rect(&output, "SETTINGS");
        let import = text_rect(&output, "IMPORT .CONF");
        assert!(settings.center().y < import.center().y);
        assert!(
            (settings.center().x - import.center().x).abs() < 1.0,
            "settings={settings:?}, import={import:?}"
        );
        assert!(
            (settings.center().x - text_rect(&output, "[-] LINK OFFLINE").left() - 60.0).abs()
                < 3.0
        );
        assert!(text_rect(&output, "SECURE TUNNEL CLIENT").bottom() <= 490.0);
        let panels: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|s| {
                if let super::egui::Shape::Rect(rect) = &s.shape {
                    if rect.fill == super::PANEL && rect.stroke.color == super::DIM {
                        return Some(rect.rect);
                    }
                }
                None
            })
            .collect();
        assert!(!panels.is_empty());
        assert!(
            panels
                .iter()
                .all(|r| r.bottom() <= 490.0 && r.right() <= 660.0)
        );
        let screens: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|s| {
                if let super::egui::Shape::Rect(rect) = &s.shape {
                    if rect.fill == super::SCREEN && rect.stroke.color == super::DIM {
                        return Some(rect.rect);
                    }
                }
                None
            })
            .collect();
        assert!(screens.iter().any(|r| r.width() > 550.0));
        click(&mut app, &ctx, settings.center());
        assert!(app.settings.is_some());
        let output = ui_frame(&mut app, &ctx, vec![]);
        assert!(text_rect(&output, "SAVE & APPLY").bottom() <= 490.0);
        click(&mut app, &ctx, text_rect(&output, "DISPLAY").center());
        let output = ui_frame(&mut app, &ctx, vec![]);
        text_rect(&output, "CRT DISPLAY: scanlines / pixel grid / vignette");
        ui_frame(
            &mut app,
            &ctx,
            vec![super::egui::Event::Key {
                key: super::egui::Key::F8,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }],
        );
        assert!(!app.settings.as_ref().unwrap().draft.effects);
        let output = ui_frame(&mut app, &ctx, vec![]);
        click(&mut app, &ctx, text_rect(&output, "< BACK").center());
        assert!(app.settings.is_some());
        let output = ui_frame(&mut app, &ctx, vec![]);
        text_rect(&output, "UNSAVED CHANGES");
        click(
            &mut app,
            &ctx,
            text_rect(&output, "DISCARD & BACK").center(),
        );
        assert!(app.settings.is_none());
    }

    #[test]
    fn split_controls_change_draft_but_are_locked_during_connection() {
        let ctx = super::egui::Context::default();
        let mut app = super::NettVpn::default();
        app.library.profiles.push(super::profiles::Profile {
            id: "fixture".into(),
            name: "home".into(),
            config: String::new(),
            sites: Default::default(),
            apps: Default::default(),
        });
        app.library.selected = Some("fixture".into());
        app.settings = Some(super::settings::Settings::new(app.library.clone()));
        app.connected = true;
        let output = ui_frame(&mut app, &ctx, vec![]);
        click(&mut app, &ctx, text_rect(&output, "SITES").center());
        let output = ui_frame(&mut app, &ctx, vec![]);
        click(
            &mut app,
            &ctx,
            text_rect(&output, "SITE SPLIT TUNNELING").center(),
        );
        assert!(
            !app.settings
                .as_ref()
                .unwrap()
                .draft
                .selected()
                .unwrap()
                .sites
                .enabled
        );
        app.connected = false;
        let output = ui_frame(&mut app, &ctx, vec![]);
        click(
            &mut app,
            &ctx,
            text_rect(&output, "SITE SPLIT TUNNELING").center(),
        );
        assert!(
            app.settings
                .as_ref()
                .unwrap()
                .draft
                .selected()
                .unwrap()
                .sites
                .enabled
        );
        assert!(!app.library.selected().unwrap().sites.enabled);
    }

    #[test]
    fn display_save_preserves_active_connection_and_profile() {
        let mut app = super::NettVpn::default();
        app.connected = true;
        let path = std::path::PathBuf::from(r"C:\test\active.conf");
        app.config = Some(path.clone());
        app.protocol = Some(super::Protocol::AmneziaWg);
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Ok(super::Completion::DisplaySaved(false, false)))
            .unwrap();
        app.pending = Some(rx);
        app.poll();
        assert!(app.connected);
        assert_eq!(app.config, Some(path));
        assert!(app.protocol == Some(super::Protocol::AmneziaWg));
        assert!(!app.library.effects);
        assert!(!app.library.motion);
    }

    #[test]
    fn ordinary_labels_are_not_selectable_but_inputs_remain_editable() {
        let ctx = super::egui::Context::default();
        let mut app = super::NettVpn::default();
        ui_frame(&mut app, &ctx, vec![]);
        assert!(!ctx.style().interaction.selectable_labels);
        let mut text = String::new();
        let mut field = None;
        let _ = ctx.run(Default::default(), |ctx| {
            super::egui::CentralPanel::default().show(ctx, |ui| {
                field = Some(ui.text_edit_singleline(&mut text).id);
            });
        });
        ctx.memory_mut(|m| m.request_focus(field.unwrap()));
        let _ = ctx.run(
            super::egui::RawInput {
                events: vec![super::egui::Event::Text("editable".into())],
                ..Default::default()
            },
            |ctx| {
                super::egui::CentralPanel::default().show(ctx, |ui| {
                    ui.text_edit_singleline(&mut text);
                });
            },
        );
        assert_eq!(text, "editable");
    }

    #[test]
    fn crt_glow_draws_real_text_halos_and_can_be_disabled() {
        let ctx = super::egui::Context::default();
        let mut app = super::NettVpn::default();
        app.library.effects = false;
        let output = ui_frame(&mut app, &ctx, vec![]);
        let count = |output: &super::egui::FullOutput| {
            output.shapes.iter().filter(|s|matches!(&s.shape,super::egui::Shape::Text(t) if t.galley.job.text=="SETTINGS")).count()
        };
        assert_eq!(count(&output), 1);
        app.library.effects = true;
        app.library.motion = false;
        let output = ui_frame(&mut app, &ctx, vec![]);
        assert!(count(&output) >= 9);
    }

    #[test]
    fn worker_does_not_block_ui_or_allow_duplicate_operations() {
        let ctx = super::egui::Context::default();
        let mut app = super::NettVpn::default();
        let (release, wait) = std::sync::mpsc::channel();
        app.start(&ctx, "CONNECTING...", move || {
            wait.recv().unwrap();
            Ok(super::Completion::Toggled(true))
        });
        app.start(&ctx, "DUPLICATE", || panic!("duplicate operation started"));
        app.poll();
        assert!(app.pending.is_some());
        assert!(!app.connected);
        assert_eq!(app.message, "CONNECTING...");
        release.send(()).unwrap();
        let result = app
            .pending
            .take()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(result).unwrap();
        app.pending = Some(rx);
        app.poll();
        assert!(app.pending.is_none());
        assert!(app.connected);
    }

    #[test]
    fn worker_failure_preserves_connection_and_unlocks_controls() {
        let mut app = super::NettVpn::default();
        app.connected = true;
        app.quit_requested = true;
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Err("UAC CANCELLED".into())).unwrap();
        app.pending = Some(rx);
        app.poll();
        assert!(app.connected);
        assert!(app.pending.is_none());
        assert_eq!(app.message, "UAC CANCELLED");
        assert!(!app.quit_requested);
        assert!(!app.allow_close);
    }

    #[test]
    fn tray_quit_waits_for_successful_disconnect() {
        let mut app = super::NettVpn::default();
        app.connected = true;
        app.quit_requested = true;
        let (tx, rx) = std::sync::mpsc::channel();
        app.pending = Some(rx);
        app.poll();
        assert!(!app.allow_close);
        tx.send(Ok(super::Completion::Toggled(false))).unwrap();
        app.poll();
        assert!(!app.connected);
        assert!(app.allow_close);
    }

    #[test]
    fn bundled_engine_is_found_without_an_installation() {
        let root = std::env::temp_dir().join(format!("nett-engine-test-{}", std::process::id()));
        let portable = root.join("engines");
        let engine = portable.join(r"AmneziaWG\amneziawg.exe");
        std::fs::create_dir_all(engine.parent().unwrap()).unwrap();
        std::fs::write(&engine, []).unwrap();
        assert_eq!(
            super::find_engine(super::Protocol::AmneziaWg, &root.join("absent"), &portable),
            Some(engine)
        );
        assert!(
            super::find_engine(super::Protocol::WireGuard, &root.join("absent"), &portable)
                .is_none()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_icon_has_complete_opaque_pixels_and_both_colors() {
        let icon = super::terminal_icon();
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        assert!(icon.rgba.chunks_exact(4).all(|pixel| pixel[3] == 255));
        assert!(
            icon.rgba
                .chunks_exact(4)
                .any(|pixel| pixel == super::LIME.to_array())
        );
        assert!(
            icon.rgba
                .chunks_exact(4)
                .any(|pixel| pixel == super::SCREEN.to_array())
        );
    }
}
