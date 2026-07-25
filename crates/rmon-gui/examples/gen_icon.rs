//! One-off generator for `assets/rmon.ico`. Run with:
//!   cargo run -p rmon-gui --example gen_icon
//! Not part of the shipped app; re-run and re-commit the .ico if the design
//! in `src/icon.rs` changes (this duplicates that pixel logic since binary
//! crates can't expose a lib for examples to import).

const BG: [u8; 4] = [28, 32, 38, 255];
const BAR: [u8; 4] = [90, 200, 90, 255];

fn rgba(size: u32) -> Vec<u8> {
    let s = size as i32;
    let radius = s / 5;
    let margin = s / 8;
    let bars: [(i32, i32, i32); 3] = [
        (s * 15 / 100, s * 35 / 100, s * 40 / 100),
        (s * 40 / 100, s * 60 / 100, s * 70 / 100),
        (s * 65 / 100, s * 85 / 100, s * 55 / 100),
    ];

    let mut buf = vec![0u8; (size * size * 4) as usize];
    for y in 0..s {
        for x in 0..s {
            if !inside_rounded_rect(x, y, s, radius) {
                continue;
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

fn inside_rounded_rect(x: i32, y: i32, s: i32, r: i32) -> bool {
    let cx = x.clamp(r, s - 1 - r);
    let cy = y.clamp(r, s - 1 - r);
    let (dx, dy) = (x - cx, y - cy);
    dx * dx + dy * dy <= r * r
}

fn main() {
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16u32, 32, 48, 256] {
        let image = ico::IconImage::from_rgba_data(size, size, rgba(size));
        icon_dir.add_entry(ico::IconDirEntry::encode(&image).expect("encode icon frame"));
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/rmon.ico");
    let file = std::fs::File::create(&path).expect("create assets/rmon.ico");
    icon_dir.write(file).expect("write assets/rmon.ico");
    println!("wrote {}", path.display());
}
