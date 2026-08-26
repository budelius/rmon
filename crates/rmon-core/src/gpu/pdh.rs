//! Per-process GPU utilization via the Windows "GPU Engine" performance
//! counters (the same data source Task Manager's GPU column uses). This
//! works for any GPU vendor with a WDDM driver, unlike NVML.

use std::collections::HashMap;

use anyhow::{Result, bail};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Performance::{
    PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW,
    PdhOpenQueryW,
};
use windows::core::PCWSTR;

const COUNTER_PATH: &str = r"\GPU Engine(*)\Utilization Percentage";

/// Samples the "GPU Engine" counter set and sums per-engine utilization by
/// owning process id.
pub struct PdhGpuMonitor {
    query: PDH_HQUERY,
    counter: PDH_HCOUNTER,
}

// The PDH handles are opaque OS handles; nothing in this type is actually
// tied to a particular thread.
unsafe impl Send for PdhGpuMonitor {}

impl PdhGpuMonitor {
    pub fn new() -> Result<Self> {
        unsafe {
            let mut query = PDH_HQUERY::default();
            let status = PdhOpenQueryW(PCWSTR::null(), 0, &mut query);
            if status != ERROR_SUCCESS.0 {
                bail!("PdhOpenQueryW failed: 0x{status:08X}");
            }

            let path_wide = to_wide(COUNTER_PATH);
            let mut counter = PDH_HCOUNTER::default();
            let status = PdhAddEnglishCounterW(query, PCWSTR(path_wide.as_ptr()), 0, &mut counter);
            if status != ERROR_SUCCESS.0 {
                let _ = PdhCloseQuery(query);
                bail!(
                    "PdhAddEnglishCounterW failed: 0x{status:08X} (no 'GPU Engine' counters on this system)"
                );
            }

            Ok(Self { query, counter })
        }
    }

    /// Returns pid -> summed GPU engine utilization percent.
    pub fn sample(&mut self) -> Result<HashMap<u32, f32>> {
        unsafe {
            let status = PdhCollectQueryData(self.query);
            if status != ERROR_SUCCESS.0 {
                bail!("PdhCollectQueryData failed: 0x{status:08X}");
            }

            let mut buffer_size: u32 = 0;
            let mut item_count: u32 = 0;
            let status = PdhGetFormattedCounterArrayW(
                self.counter,
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                None,
            );
            if status != PDH_MORE_DATA && status != ERROR_SUCCESS.0 {
                // No instances yet (e.g. right after the first collect) is fine.
                return Ok(HashMap::new());
            }
            if buffer_size == 0 || item_count == 0 {
                return Ok(HashMap::new());
            }

            let item_size = std::mem::size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>();
            let byte_len = buffer_size as usize;
            let mut buffer: Vec<u8> = vec![0u8; byte_len];
            let items_ptr = buffer.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;

            let status = PdhGetFormattedCounterArrayW(
                self.counter,
                PDH_FMT_DOUBLE,
                &mut buffer_size,
                &mut item_count,
                Some(items_ptr),
            );
            if status != ERROR_SUCCESS.0 {
                bail!("PdhGetFormattedCounterArrayW (fill) failed: 0x{status:08X}");
            }

            let mut totals: HashMap<u32, f32> = HashMap::new();
            for i in 0..item_count as usize {
                if (i + 1) * item_size > byte_len {
                    break;
                }
                let item = &*items_ptr.add(i);
                if item.szName.is_null() {
                    continue;
                }
                let Ok(instance_name) = item.szName.to_string() else {
                    continue;
                };
                let Some(pid) = extract_pid(&instance_name) else {
                    continue;
                };
                if item.FmtValue.CStatus != 0 {
                    continue;
                }
                let value = item.FmtValue.Anonymous.doubleValue;
                if !value.is_finite() || value < 0.0 {
                    continue;
                }
                *totals.entry(pid).or_insert(0.0) += value as f32;
            }

            Ok(totals)
        }
    }
}

impl Drop for PdhGpuMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = PdhCloseQuery(self.query);
        }
    }
}

/// Parses a pid out of a "GPU Engine" instance name, e.g.
/// `pid_1234_luid_0x00000000_0x0000ABCD_phys_0_eng_0_engtype_3D`.
fn extract_pid(instance_name: &str) -> Option<u32> {
    let rest = instance_name.strip_prefix("pid_")?;
    let end = rest.find('_')?;
    rest[..end].parse().ok()
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pid_from_instance_name() {
        assert_eq!(
            extract_pid("pid_1234_luid_0x00000000_0x0000ABCD_phys_0_eng_0_engtype_3D"),
            Some(1234)
        );
        assert_eq!(extract_pid("_total"), None);
    }
}
