use eframe::egui;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows_sys::Win32::UI::WindowsAndMessaging::{SW_RESTORE, SetForegroundWindow, ShowWindow};

fn restore_window(hwnd: isize) {
    // A hidden window cannot repaint to apply queued egui viewport commands.
    unsafe {
        ShowWindow(hwnd as _, SW_RESTORE);
        SetForegroundWindow(hwnd as _);
    }
}
use std::sync::mpsc::{self, Receiver};
use tray_icon::{
    Icon, TrayIcon, TrayIconBuilder,
    menu::{Menu, MenuEvent, MenuItem},
};

pub struct Tray {
    icon: TrayIcon,
    pub quit: Receiver<()>,
    connected: bool,
}

fn icon(connected: bool) -> Icon {
    let mut data = super::terminal_icon();
    for pixel in data.rgba.chunks_exact_mut(4) {
        if pixel == super::LIME.to_array() {
            if !connected {
                pixel.copy_from_slice(&[255, 255, 255, 255]);
            }
        } else {
            pixel.copy_from_slice(&[0, 0, 0, 0]);
        }
    }
    Icon::from_rgba(data.rgba, data.width, data.height).expect("fixed 32x32 icon")
}

impl Tray {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let RawWindowHandle::Win32(window) = cc.window_handle()?.as_raw() else {
            return Err("TRAY REQUIRES A WINDOWS WINDOW".into());
        };
        let hwnd = window.hwnd.get();
        let menu = Menu::new();
        let show = MenuItem::new("s33", true, None);
        let quit = MenuItem::new("qu1t", true, None);
        menu.append_items(&[&show, &quit])?;
        let icon = TrayIconBuilder::new()
            .with_tooltip("nett - waiting")
            .with_icon(icon(false))
            .with_menu(Box::new(menu))
            .build()?;
        let (tx, rx) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let show_id = show.id().clone();
        let quit_id = quit.id().clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if event.id == show_id || event.id == quit_id {
                restore_window(hwnd);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                if event.id == quit_id {
                    let _ = tx.send(());
                }
                ctx.request_repaint();
            }
        }));
        Ok(Self {
            icon,
            quit: rx,
            connected: false,
        })
    }

    pub fn update(&mut self, connected: bool) -> Result<(), String> {
        if self.connected != connected {
            self.icon
                .set_icon(Some(icon(connected)))
                .map_err(|e| e.to_string())?;
            self.icon
                .set_tooltip(Some(if connected {
                    "nett - wired"
                } else {
                    "nett - waiting"
                }))
                .map_err(|e| e.to_string())?;
            self.connected = connected;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn hidden_window_is_restored_without_an_egui_frame() {
        use windows_sys::Win32::UI::WindowsAndMessaging::*;
        unsafe {
            let hwnd = CreateWindowExW(
                0,
                windows_sys::w!("STATIC"),
                windows_sys::w!("nett-tray-test"),
                WS_POPUP,
                -32000,
                -32000,
                1,
                1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            );
            assert!(!hwnd.is_null());
            assert_eq!(IsWindowVisible(hwnd), 0);
            super::restore_window(hwnd as isize);
            let visible = IsWindowVisible(hwnd);
            DestroyWindow(hwnd);
            assert_ne!(visible, 0);
        }
    }
}
