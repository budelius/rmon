//! Procedurally draws rMon's icon (a dark rounded square with three
//! ascending bars, echoing the CPU sparkline) so no icon asset file is
//! needed for the window icon or tray icon at runtime.

const BG: [u8; 4] = [28, 32, 38, 255];
const BAR: [u8; 4] = [90, 200, 90, 255];

/// Returns `size * size` RGBA8 pixels (straight, unmultiplied alpha).
/// `size` should be a multiple of 4.
pub fn rgba(size: u32) -> Vec<u8> {
    let s = size as i32;
    let radius = s / 5;
    let margin = s / 8;
    // Three ascending bars: (x_start, x_end, height_from_bottom).
    let bars: [(i32, i32, i32); 3] = [
        (s * 15 / 100, s * 35 / 100, s * 40 / 100),
        (s * 40 / 100, s * 60 / 100, s * 70 / 100),
        (s * 65 / 100, s * 85 / 100, s * 55 / 100),
    ];

    let mut buf = vec![0u8; (size * size * 4) as usize];
    for y in 0..s {
        for x in 0..s {
            if !inside_rounded_rect(x, y, s, radius) {
                continue; // leave fully transparent
            }
            let mut color = BG;
            for &(x0, x1, h) in &bars {
                if x >= x0 && x < x1 && y >= s - margin - h && y < s - margin {
                    color = BAR;
                }
            }
            let idx = ((y * s + x) * 4) as usize;
            buf[idx..idx + 4].copy_from_slice(&color);
        }
    }
    buf
}

/// Standard per-pixel rounded-rect test: clamp the pixel into the inset
/// rectangle (inset by `r` on each side) and check it's within `r` of that
/// clamped point. Flat edges always pass; only the four corners get curved.
fn inside_rounded_rect(x: i32, y: i32, s: i32, r: i32) -> bool {
    let cx = x.clamp(r, s - 1 - r);
    let cy = y.clamp(r, s - 1 - r);
    let (dx, dy) = (x - cx, y - cy);
    dx * dx + dy * dy <= r * r
}
