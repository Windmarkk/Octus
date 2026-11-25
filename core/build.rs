//! Derleme zamanında IEEE OUI tablosunu (`data/oui.csv`) statik diziye çevirir.
//! Çalışma anında dış istek yapılmaz.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=data/oui.csv");
    println!("cargo:rerun-if-changed=build.rs");

    let Ok(out_dir) = env::var("OUT_DIR") else {
        panic!("OUT_DIR tanımlı değil");
    };
    let out_path = PathBuf::from(out_dir).join("oui_table.rs");

    let mut table: BTreeMap<u32, String> = BTreeMap::new();
    match fs::read_to_string("data/oui.csv") {
        Ok(text) => {
            for line in text.lines().skip(1) {
                let fields = split_csv(line);
                if fields.len() < 3 {
                    continue;
                }
                let assignment = fields[1].trim();
                // Yalnızca MA-L (24 bit) kayıtları; MA-M/MA-S için önek eşleşmesi yanıltıcı olur.
                if assignment.len() != 6 {
                    continue;
                }
                if let Ok(key) = u32::from_str_radix(assignment, 16) {
                    table
                        .entry(key)
                        .or_insert_with(|| fields[2].trim().to_string());
                }
            }
        }
        Err(_) => {
            println!("cargo:warning=data/oui.csv bulunamadı; üretici tespiti boş çalışacak");
        }
    }

    let mut code = String::from("pub static OUI_TABLE: &[(u32, &str)] = &[\n");
    for (key, name) in &table {
        code.push_str(&format!("    (0x{key:06X}, {name:?}),\n"));
    }
    code.push_str("];\n");

    if let Err(e) = fs::write(&out_path, code) {
        panic!("oui_table.rs yazılamadı ({}): {e}", out_path.display());
    }
}

/// Tırnak içindeki virgülleri koruyan minimal CSV ayrıştırıcı.
fn split_csv(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}
