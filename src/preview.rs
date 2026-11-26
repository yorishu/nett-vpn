// Screenshot-only fixture: never loads a user's vault, creates a tray, or connects.
pub fn app() -> super::NettVpn {
    use super::profiles::{Library, Mode, Profile, Rules};
    let screen = std::env::var("NETT_PREVIEW_SCREEN").unwrap_or_else(|_| "home".into());
    let library = Library {
        vpn: crate::profiles::VpnConfig {
            profiles: vec![Profile {
                id: "preview".into(),
                name: "home / amneziawg".into(),
                config: "[Interface]\nJc=4".into(),
            }],
            selected: Some("preview".into()),
        },
        user: crate::profiles::UserConfig {
            sites: Rules {
                enabled: true,
                mode: Mode::Direct,
                entries: vec![
                    "192.168.10.0/24".into(),
                    "example.com".into(),
                    "host.ts.net:8766".into(),
                ],
            },
            apps: Rules {
                enabled: true,
                mode: Mode::Direct,
                entries: vec![
                    r"C:\Apps\Discord.exe".into(),
                    r"C:\Apps\qbittorrent.exe".into(),
                ],
            },
            effects: std::env::var_os("NETT_PREVIEW_CLEAN").is_none(),
            motion: screen == "glitch",
            kill_switch: ["blocked", "wired"].contains(&screen.as_str()),
        },
    };
    let mut app = super::NettVpn::default();
    app.protocol = Some(super::Protocol::AmneziaWg);
    app.message = "READY / OFFLINE".into();
    app.display_started = std::time::Instant::now() - std::time::Duration::from_secs_f64(6.8);
    app.connected = ["wired", "unverified"].contains(&screen.as_str());
    app.verified = screen == "wired";
    app.guarded = screen == "blocked";
    if app.verified {
        app.message = "VPN TUNNEL VERIFIED".into();
    }
    if app.guarded {
        app.message = "VPN LOST - KILL SWITCH BLOCKING".into();
    }
    if !["home", "glitch", "wired", "unverified", "blocked"].contains(&screen.as_str()) {
        app.settings = Some(super::settings::Settings::preview(library.clone(), &screen));
    }
    app.library = library;
    app
}
