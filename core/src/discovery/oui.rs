//! MAC önekinden üretici adı. Tablo `build.rs` ile derleme zamanında gömülür.

use pnet::util::MacAddr;

include!(concat!(env!("OUT_DIR"), "/oui_table.rs"));

/// MAC'in ilk 3 baytına (OUI) göre üretici adı.
pub fn vendor_of(mac: MacAddr) -> Option<&'static str> {
    let key = (u32::from(mac.0) << 16) | (u32::from(mac.1) << 8) | u32::from(mac.2);
    OUI_TABLE
        .binary_search_by_key(&key, |(k, _)| *k)
        .ok()
        .map(|i| OUI_TABLE[i].1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(OUI_TABLE.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn every_entry_resolves() {
        for &(key, name) in OUI_TABLE {
            let mac = MacAddr::new(
                (key >> 16) as u8,
                (key >> 8) as u8,
                key as u8,
                0,
                0,
                0,
            );
            assert_eq!(vendor_of(mac), Some(name));
        }
    }

    #[test]
    fn unknown_prefix_is_none() {
        // Tablo tam listeyi içerir; tanımsız önek için tüm bitleri 1 olan yerel-yönetimli
        // bir adres seçilir (IEEE MA-L kayıtlarında bulunmaz).
        let mac = MacAddr::new(0xFE, 0xFF, 0xFF, 0, 0, 0);
        assert_eq!(vendor_of(mac), None);
    }
}
