//! Host system metrics for `ReportNodeStatus` — the Rust analogue of XrayR's
//! `common/serverstatus.GetSystemInfo` (CPU%, memory%, root-disk%, uptime).

use std::path::Path;

use sysinfo::{Disks, System};

use crate::api::NodeStatus;

/// Sample CPU / memory / disk usage and process-host uptime.
///
/// CPU usage needs two samples spaced by the platform minimum interval, so this
/// is async; it is only ever called from the periodic reporting task.
pub async fn get_system_info() -> NodeStatus {
    let mut sys = System::new();

    // CPU: two refreshes separated by the minimum interval.
    sys.refresh_cpu_usage();
    tokio::time::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL).await;
    sys.refresh_cpu_usage();
    let cpu = f64::from(sys.global_cpu_usage());

    sys.refresh_memory();
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let mem = if total_mem > 0 {
        used_mem as f64 / total_mem as f64 * 100.0
    } else {
        0.0
    };

    let disk = root_disk_usage();
    let uptime = System::uptime();

    NodeStatus {
        cpu,
        mem,
        disk,
        uptime,
    }
}

/// Used-percentage of the filesystem mounted at `/` (falls back to the largest
/// disk, then 0 when no disks are visible).
fn root_disk_usage() -> f64 {
    let disks = Disks::new_with_refreshed_list();
    let root = Path::new("/");

    let mut chosen: Option<(u64, u64)> = None; // (total, available)
    for d in disks.list() {
        if d.mount_point() == root {
            chosen = Some((d.total_space(), d.available_space()));
            break;
        }
        // Track the largest disk as a fallback.
        if chosen.is_none_or(|(t, _)| d.total_space() > t) {
            chosen = Some((d.total_space(), d.available_space()));
        }
    }

    match chosen {
        Some((total, avail)) if total > 0 => {
            total.saturating_sub(avail) as f64 / total as f64 * 100.0
        }
        _ => 0.0,
    }
}
