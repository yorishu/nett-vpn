use crate::{Color32, LIME, egui};

fn vignette(rect: egui::Rect) -> egui::epaint::Mesh {
    let mut mesh = egui::epaint::Mesh::default();
    const COLS: usize = 24;
    const ROWS: usize = 20;
    for y in 0..=ROWS {
        for x in 0..=COLS {
            let u = x as f32 / COLS as f32;
            let v = y as f32 / ROWS as f32;
            let radius = (((u - 0.5) * 2.0).powi(2) + ((v - 0.5) * 2.0).powi(2)) / 2.0;
            let alpha = (radius.powf(1.7) * 96.0) as u8;
            mesh.colored_vertex(
                egui::pos2(
                    rect.left() + u * rect.width(),
                    rect.top() + v * rect.height(),
                ),
                Color32::from_black_alpha(alpha),
            );
            if x < COLS && y < ROWS {
                let i = (y * (COLS + 1) + x) as u32;
                mesh.add_triangle(i, i + 1, i + COLS as u32 + 1);
                mesh.add_triangle(i + 1, i + COLS as u32 + 2, i + COLS as u32 + 1);
            }
        }
    }
    mesh
}

pub fn paint(ctx: &egui::Context, rect: egui::Rect, elapsed: f64, motion: bool) {
    let inner = rect.shrink(8.0);
    let painter = ctx
        .layer_painter(egui::LayerId::new(
            egui::Order::Tooltip,
            egui::Id::new("crt-overlay"),
        ))
        .with_clip_rect(inner);
    // Copy only bright phosphor text, retaining each original clipping rectangle.
    let texts = ctx.graphics(|graphics| {
        graphics
            .get(egui::LayerId::background())
            .map(|list| {
                list.all_entries()
                    .filter_map(|entry| {
                        if let egui::Shape::Text(text) = &entry.shape {
                            if text.override_text_color == Some(LIME)
                                || text
                                    .galley
                                    .job
                                    .sections
                                    .iter()
                                    .any(|s| s.format.color == LIME)
                            {
                                return Some((entry.clip_rect, text.clone()));
                            }
                        }
                        None
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    });
    for (clip, text) in &texts {
        let glow = painter.with_clip_rect(clip.intersect(inner));
        for (x, y, alpha) in [
            (-1.0, 0.0, 38),
            (1.0, 0.0, 38),
            (0.0, -1.0, 30),
            (0.0, 1.0, 30),
            (-2.5, 0.0, 12),
            (2.5, 0.0, 12),
            (0.0, -2.5, 10),
            (0.0, 2.5, 10),
        ] {
            let mut copy = text.clone();
            copy.pos += egui::vec2(x, y);
            copy.override_text_color = Some(Color32::from_rgba_unmultiplied(156, 255, 68, alpha));
            glow.add(copy);
        }
    }
    // Paint-only effects leave all hit targets and keyboard focus unchanged.
    let mut y = inner.top();
    while y < inner.bottom() {
        painter.hline(
            inner.x_range(),
            y,
            egui::Stroke::new(1.0_f32, Color32::from_black_alpha(44)),
        );
        painter.hline(
            inner.x_range(),
            y + 1.0,
            egui::Stroke::new(0.5_f32, Color32::from_rgba_unmultiplied(156, 255, 68, 8)),
        );
        y += 3.0;
    }
    let mut x = inner.left();
    while x < inner.right() {
        painter.vline(
            x,
            inner.y_range(),
            egui::Stroke::new(1.0_f32, Color32::from_black_alpha(8)),
        );
        x += 3.0;
    }
    painter.add(egui::Shape::mesh(vignette(inner)));
    if motion {
        let sweep = inner.top() + ((elapsed % 5.5) / 5.5) as f32 * inner.height();
        for band in 0..12 {
            let alpha = ((1.0 - (band as f32 - 5.5).abs() / 6.0) * 26.0) as u8;
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(inner.left(), sweep + band as f32 * 2.0),
                    egui::vec2(inner.width(), 2.0),
                ),
                0.0,
                Color32::from_rgba_unmultiplied(156, 255, 68, alpha),
            );
        }
        let glitch = elapsed % 7.0;
        if glitch > 6.72 {
            let top = inner.top() + inner.height() * (if glitch > 6.88 { 0.62 } else { 0.34 });
            let strip = egui::Rect::from_min_size(
                egui::pos2(inner.left(), top),
                egui::vec2(inner.width(), 12.0),
            );
            painter.rect_filled(strip, 0.0, Color32::from_black_alpha(30));
            for (clip, text) in &texts {
                for (offset, color) in [
                    (5.0, Color32::from_rgba_unmultiplied(156, 255, 68, 110)),
                    (-3.0, Color32::from_rgba_unmultiplied(90, 165, 255, 65)),
                ] {
                    let mut copy = text.clone();
                    copy.pos.x += offset;
                    copy.override_text_color = Some(color);
                    painter
                        .with_clip_rect(clip.intersect(strip).intersect(inner))
                        .add(copy);
                }
            }
            painter.hline(
                strip.x_range(),
                strip.top(),
                egui::Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(156, 255, 68, 65)),
            );
        }
        let tick = (elapsed * 12.0) as u32;
        for i in 0..28u32 {
            let seed = tick
                .wrapping_mul(747796405)
                .wrapping_add(i.wrapping_mul(2891336453));
            let x = inner.left() + (seed % 1000) as f32 / 1000.0 * inner.width();
            let y = inner.top() + ((seed.rotate_left(13)) % 1000) as f32 / 1000.0 * inner.height();
            painter.rect_filled(
                egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(2.0, 1.0)),
                0.0,
                Color32::from_white_alpha(24),
            );
        }
        if elapsed < 0.5 {
            let shown = (elapsed / 0.5) as f32 * inner.height();
            painter.rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(inner.left(), inner.top() + shown),
                    inner.right_bottom(),
                ),
                0.0,
                crate::BG,
            );
            painter.hline(
                inner.x_range(),
                inner.top() + shown,
                egui::Stroke::new(1.0_f32, LIME),
            );
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
    }
}

pub fn reduced_motion() -> bool {
    let mut animations = 1i32;
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::SystemParametersInfoW(
            0x1042,
            0,
            (&mut animations as *mut i32).cast(),
            0,
        );
    }
    animations == 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn vignette_is_transparent_at_center_and_darker_at_edges() {
        let rect = crate::egui::Rect::from_min_size(
            crate::egui::Pos2::ZERO,
            crate::egui::vec2(660.0, 490.0),
        );
        let mesh = super::vignette(rect);
        assert_eq!(mesh.vertices[10 * 25 + 12].color.a(), 0);
        assert_eq!(mesh.vertices[0].color.a(), 96);
        assert!(
            mesh.indices
                .iter()
                .all(|i| (*i as usize) < mesh.vertices.len())
        );
        assert!(mesh.vertices.iter().all(|v| rect.contains(v.pos)));
    }
}
