use crate::{
    DIM, LIME, PANEL, RichText, Vec2, egui,
    profiles::{Library, Mode, Rules},
};

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Profiles,
    Sites,
    Apps,
    Display,
}

pub enum Action {
    Save(Library),
    SaveDisplay(bool, bool),
    Import,
    PickApp,
    Close,
}

pub struct Settings {
    pub draft: Library,
    saved: Library,
    confirm_discard: bool,
    page: Page,
    input: String,
    error: String,
    delete: Option<String>,
}

impl Settings {
    #[cfg(feature = "ui-preview")]
    pub fn preview(draft: Library, page: &str) -> Self {
        let mut result = Self::new(draft);
        result.page = match page {
            "sites" => Page::Sites,
            "apps" => Page::Apps,
            "display" => Page::Display,
            _ => Page::Profiles,
        };
        result
    }
    pub fn new(draft: Library) -> Self {
        Self {
            saved: draft.clone(),
            confirm_discard: false,
            draft,
            page: Page::Profiles,
            input: String::new(),
            error: String::new(),
            delete: None,
        }
    }

    pub fn accept_saved(&mut self, library: Library) {
        self.saved = library.clone();
        self.draft = library;
        self.error.clear();
        self.delete = None;
        self.confirm_discard = false;
    }

    pub fn accept_display(&mut self, effects: bool, motion: bool) {
        self.saved.effects = effects;
        self.saved.motion = motion;
        self.draft.effects = effects;
        self.draft.motion = motion;
        if self.draft == self.saved {
            self.confirm_discard = false;
        }
    }

    pub fn add_app(&mut self, path: String) {
        if let Some(profile) = self.draft.selected_mut() {
            if !profile
                .apps
                .entries
                .iter()
                .any(|e| e.eq_ignore_ascii_case(&path))
            {
                profile.apps.entries.push(path);
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, locked: bool, busy: bool) -> Option<Action> {
        let mut action = None;
        ui.horizontal(|ui| {
            if ui.button(RichText::new("< BACK").monospace()).clicked() {
                if self.draft == self.saved {
                    action = Some(Action::Close);
                } else {
                    self.confirm_discard = true;
                }
            }
            ui.label(
                RichText::new("settings / control deck")
                    .monospace()
                    .color(LIME)
                    .strong(),
            );
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            for (page, label) in [
                (Page::Profiles, "PROFILES"),
                (Page::Sites, "SITES"),
                (Page::Apps, "APPS"),
                (Page::Display, "DISPLAY"),
            ] {
                if ui
                    .selectable_label(self.page == page, RichText::new(label).monospace())
                    .clicked()
                {
                    self.page = page;
                    self.input.clear();
                    self.error.clear();
                    self.delete = None;
                }
            }
        });
        ui.separator();
        if locked && self.page != Page::Display {
            ui.label(
                RichText::new("[LOCKED] Disconnect to edit profiles and routing.")
                    .monospace()
                    .color(DIM),
            );
        }
        egui::ScrollArea::vertical().auto_shrink([false,false]).id_salt("settings-scroll").max_height(270.0).min_scrolled_height(270.0).show(ui, |ui| {
            ui.add_enabled_ui(!busy && (!locked || self.page==Page::Display), |ui| {
                match self.page {
                    Page::Profiles => {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("encrypted profile library").monospace().color(DIM));
                            if ui.button(RichText::new("+ IMPORT .CONF").monospace()).clicked() { action=Some(Action::Import); }
                        });
                        if self.draft.profiles.is_empty() { ui.label("No profiles. Import a WireGuard or AmneziaWG config."); }
                        let mut remove=None;
                        for profile in &mut self.draft.profiles {
                            egui::Frame::new().fill(PANEL).inner_margin(10.0).show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let selected=self.draft.selected.as_ref()==Some(&profile.id);
                                    if ui.selectable_label(selected, RichText::new(if selected {"[SELECTED]"}else{"[  USE   ]"}).monospace()).clicked() {
                                        self.draft.selected=Some(profile.id.clone());
                                    }
                                    ui.add(egui::TextEdit::singleline(&mut profile.name).desired_width(220.0).char_limit(64)).on_hover_text("Profile name");
                                    ui.label(RichText::new(if profile.protocol()==crate::Protocol::AmneziaWg {"AWG"}else{"WG"}).monospace().color(DIM));
                                    if ui.button(RichText::new("DEL").monospace()).clicked() { self.delete=Some(profile.id.clone()); }
                                });
                                if self.delete.as_ref()==Some(&profile.id) {
                                    ui.horizontal(|ui| {
                                        ui.label("Delete this saved profile?");
                                        if ui.button("DELETE").clicked() { remove=Some(profile.id.clone()); self.delete=None; }
                                        if ui.button("CANCEL").clicked() { self.delete=None; }
                                    });
                                }
                            });
                            ui.add_space(8.0);
                        }
                        if let Some(id)=remove {
                            self.draft.profiles.retain(|p|p.id!=id);
                            if self.draft.selected.as_ref()==Some(&id) { self.draft.selected=self.draft.profiles.first().map(|p|p.id.clone()); }
                        }
                    }
                    Page::Sites | Page::Apps => {
                        let apps=self.page==Page::Apps;
                        if let Some(profile)=self.draft.selected_mut() {
                            ui.label(RichText::new(format!("profile / {}",profile.name)).monospace().color(DIM));
                            let rules=if apps {&mut profile.apps}else{&mut profile.sites};
                            ui.checkbox(&mut rules.enabled, if apps {"APP SPLIT TUNNELING"}else{"SITE SPLIT TUNNELING"});
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut rules.mode, Mode::ViaVpn, "VIA VPN");
                                ui.selectable_value(&mut rules.mode, Mode::Direct, "DIRECTLY");
                            });
                            ui.label(RichText::new(if rules.mode==Mode::Direct {"Listed destinations bypass VPN; other traffic uses VPN."}else{"Only listed destinations use VPN; other traffic is direct."}).monospace().color(DIM));
                            ui.label(RichText::new("Direct exceptions override VPN inclusions across both lists.").small().color(DIM));
                            ui.add_space(12.0);
                            if apps {
                                if ui.button(RichText::new("+ SELECT .EXE").monospace()).clicked() { action=Some(Action::PickApp); }
                                ui.label(RichText::new("Full executable paths. Restart apps after reconnecting.").small().color(DIM));
                            } else {
                                ui.label(RichText::new("DOMAIN / IP / CIDR / HOST:PORT").monospace().small().color(DIM));
                                ui.horizontal(|ui| {
                                    let input=ui.add_sized([350.0,30.0],egui::TextEdit::singleline(&mut self.input).hint_text("example.com or 192.168.10.0/24"));
                                    if ui.button("+ ADD").clicked() || (input.lost_focus() && ui.input(|i|i.key_pressed(egui::Key::Enter))) {
                                        let value=self.input.trim().to_owned();
                                        let mut candidate=rules.clone(); candidate.enabled=false; candidate.entries.push(value);
                                        match crate::split::validate_rules(&candidate,false) {
                                            Ok(())=>{ rules.entries=candidate.entries; self.input.clear(); self.error.clear(); },
                                            Err(e)=>self.error=e,
                                        }
                                    }
                                });
                            }
                            ui.add_space(8.0);
                            entries(ui,rules);
                        } else { ui.label("Select or import a profile first."); }
                    }
                    Page::Display => {
                        ui.label(RichText::new("phosphor / display controls").monospace().color(LIME));
                        ui.add_space(12.0);
                        ui.checkbox(&mut self.draft.effects,"CRT DISPLAY: scanlines / pixel grid / vignette");
                        ui.checkbox(&mut self.draft.motion,"ANIMATION: raster reveal / soft sweep / rare glitches");
                        ui.add_space(8.0);
                        ui.label(RichText::new("F8 toggles effects immediately. Windows reduced-motion preferences are respected.").monospace().color(DIM));
                    }
                }
            });
        });
        ui.separator();
        if !self.error.is_empty() {
            ui.label(
                RichText::new(&self.error)
                    .monospace()
                    .color(egui::Color32::LIGHT_RED),
            );
        }
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !busy && (!locked || self.page == Page::Display),
                    egui::Button::new(RichText::new("SAVE & APPLY").monospace().strong())
                        .min_size(Vec2::new(145.0, 32.0)),
                )
                .clicked()
            {
                if self.page == Page::Display {
                    action = Some(Action::SaveDisplay(self.draft.effects, self.draft.motion));
                } else {
                    match self.draft.validate() {
                        Ok(()) => action = Some(Action::Save(self.draft.clone())),
                        Err(e) => self.error = e,
                    }
                }
            }
            ui.label(
                RichText::new(if self.page == Page::Display {
                    "Display settings apply immediately."
                } else {
                    "Changes apply on next connection."
                })
                .monospace()
                .small()
                .color(DIM),
            );
        });
        if self.confirm_discard {
            egui::Modal::new(egui::Id::new("unsaved-settings")).show(ui.ctx(), |ui| {
                ui.label(
                    RichText::new("UNSAVED CHANGES")
                        .monospace()
                        .color(LIME)
                        .strong(),
                );
                ui.label("Use SAVE & APPLY to keep your profile and routing edits.");
                ui.horizontal(|ui| {
                    if ui.button("KEEP EDITING").clicked() {
                        self.confirm_discard = false;
                    }
                    if ui.button("DISCARD & BACK").clicked() {
                        action = Some(Action::Close);
                    }
                });
            });
        }
        action
    }
}

fn entries(ui: &mut egui::Ui, rules: &mut Rules) {
    let mut remove = None;
    if rules.entries.is_empty() {
        ui.label(RichText::new("[ EMPTY LIST ]").monospace().color(DIM));
    }
    for (index, entry) in rules.entries.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.add(egui::Label::new(RichText::new(entry).monospace()).wrap());
            if ui.small_button("DEL").clicked() {
                remove = Some(index);
            }
        });
        ui.separator();
    }
    if let Some(index) = remove {
        rules.entries.remove(index);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn saving_keeps_current_tab_and_clears_dirty_state() {
        let mut settings = super::Settings::new(Default::default());
        settings.page = super::Page::Apps;
        settings.draft.motion = false;
        settings.confirm_discard = true;
        let saved = settings.draft.clone();
        settings.accept_saved(saved.clone());
        assert!(settings.page == super::Page::Apps);
        assert!(settings.draft == saved && settings.saved == saved);
        assert!(!settings.confirm_discard);
        settings.draft.effects = false;
        settings.accept_display(false, false);
        assert!(settings.draft == settings.saved);
    }
    #[test]
    fn animation_can_be_edited_and_saved_while_vpn_is_active() {
        let ctx = crate::egui::Context::default();
        let mut settings = super::Settings::new(Default::default());
        settings.page = super::Page::Display;
        fn frame(
            settings: &mut super::Settings,
            ctx: &crate::egui::Context,
            events: Vec<crate::egui::Event>,
        ) -> (crate::egui::FullOutput, Option<super::Action>) {
            let mut action = None;
            let output = ctx.run(
                crate::egui::RawInput {
                    screen_rect: Some(crate::egui::Rect::from_min_size(
                        crate::egui::Pos2::ZERO,
                        crate::egui::vec2(660.0, 490.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    crate::egui::CentralPanel::default().show(ctx, |ui| {
                        action = settings.show(ui, true, false);
                    });
                },
            );
            (output, action)
        }
        fn center(output: &crate::egui::FullOutput, label: &str) -> crate::egui::Pos2 {
            output
                .shapes
                .iter()
                .find_map(|shape| {
                    if let crate::egui::Shape::Text(t) = &shape.shape {
                        (t.galley.job.text == label)
                            .then(|| t.galley.rect.translate(t.pos.to_vec2()).center())
                    } else {
                        None
                    }
                })
                .unwrap()
        }
        let (output, _) = frame(&mut settings, &ctx, vec![]);
        let checkbox = center(
            &output,
            "ANIMATION: raster reveal / soft sweep / rare glitches",
        );
        for pressed in [true, false] {
            frame(
                &mut settings,
                &ctx,
                vec![
                    crate::egui::Event::PointerMoved(checkbox),
                    crate::egui::Event::PointerButton {
                        pos: checkbox,
                        button: crate::egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            );
        }
        assert!(!settings.draft.motion);
        let (output, _) = frame(&mut settings, &ctx, vec![]);
        let save = center(&output, "SAVE & APPLY");
        let mut result = None;
        for pressed in [true, false] {
            result = frame(
                &mut settings,
                &ctx,
                vec![
                    crate::egui::Event::PointerMoved(save),
                    crate::egui::Event::PointerButton {
                        pos: save,
                        button: crate::egui::PointerButton::Primary,
                        pressed,
                        modifiers: Default::default(),
                    },
                ],
            )
            .1;
        }
        assert!(matches!(
            result,
            Some(super::Action::SaveDisplay(true, false))
        ));
    }
}
