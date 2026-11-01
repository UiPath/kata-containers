// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::convert::From;
use std::sync::LazyLock;

use cgroups::fs::hierarchies::is_cgroup2_unified_mode;
use containerd_shim_protos::cgroups::metrics;
use containerd_shim_protos::cgroups_v2::metrics as metrics_v2;
use protobuf::Message;

use super::{StatsInfo, StatsInfoValue};

static CGROUP_V2: LazyLock<bool> = LazyLock::new(is_cgroup2_unified_mode);

impl From<Option<agent::StatsContainerResponse>> for StatsInfo {
    fn from(c_stats: Option<agent::StatsContainerResponse>) -> Self {
        StatsInfo::from_agent(c_stats, *CGROUP_V2)
    }
}

// TODO: trans from agent proto?
impl StatsInfo {
    // Report the metrics type of the host cgroup version, as the Go shim does.
    // v1 metrics drop the memory.stat keys of a v2 guest (anon, pgfault,
    // inactive_file, ...).
    fn from_agent(c_stats: Option<agent::StatsContainerResponse>, cgroup_v2: bool) -> Self {
        let mut metric = metrics::Metrics::new();
        let stats = match c_stats {
            None => {
                return StatsInfo { value: None };
            }
            Some(stats) => stats,
        };

        if cgroup_v2 {
            return metrics_v2(stats);
        }

        if let Some(cg_stats) = stats.cgroup_stats {
            if let Some(cpu) = cg_stats.cpu_stats {
                // set protobuf cpu stat
                let mut p_cpu = metrics::CPUStat::new();
                if let Some(usage) = cpu.cpu_usage {
                    let mut p_usage = metrics::CPUUsage::new();
                    p_usage.set_total(usage.total_usage);
                    p_usage.set_per_cpu(usage.percpu_usage);
                    p_usage.set_kernel(usage.usage_in_kernelmode);
                    p_usage.set_user(usage.usage_in_usermode);

                    // set protobuf cpu usage
                    p_cpu.set_usage(p_usage);
                }

                if let Some(throttle) = cpu.throttling_data {
                    let mut p_throttle = metrics::Throttle::new();
                    p_throttle.set_periods(throttle.periods);
                    p_throttle.set_throttled_time(throttle.throttled_time);
                    p_throttle.set_throttled_periods(throttle.throttled_periods);

                    // set protobuf cpu usage
                    p_cpu.set_throttling(p_throttle);
                }

                metric.set_cpu(p_cpu);
            }

            if let Some(m_stats) = cg_stats.memory_stats {
                let mut p_m = metrics::MemoryStat::new();
                p_m.set_cache(m_stats.cache);
                // memory usage
                if let Some(m_data) = m_stats.usage {
                    let mut p_m_entry = metrics::MemoryEntry::new();
                    p_m_entry.set_usage(m_data.usage);
                    p_m_entry.set_limit(m_data.limit);
                    p_m_entry.set_failcnt(m_data.failcnt);
                    p_m_entry.set_max(m_data.max_usage);

                    p_m.set_usage(p_m_entry);
                }
                // memory swap_usage
                if let Some(m_data) = m_stats.swap_usage {
                    let mut p_m_entry = metrics::MemoryEntry::new();
                    p_m_entry.set_usage(m_data.usage);
                    p_m_entry.set_limit(m_data.limit);
                    p_m_entry.set_failcnt(m_data.failcnt);
                    p_m_entry.set_max(m_data.max_usage);

                    p_m.set_swap(p_m_entry);
                }
                // memory kernel_usage
                if let Some(m_data) = m_stats.kernel_usage {
                    let mut p_m_entry = metrics::MemoryEntry::new();
                    p_m_entry.set_usage(m_data.usage);
                    p_m_entry.set_limit(m_data.limit);
                    p_m_entry.set_failcnt(m_data.failcnt);
                    p_m_entry.set_max(m_data.max_usage);

                    p_m.set_kernel(p_m_entry);
                }

                for (k, v) in m_stats.stats {
                    match k.as_str() {
                        "dirty" => p_m.set_dirty(v),
                        "rss" => p_m.set_rss(v),
                        "rss_huge" => p_m.set_rss_huge(v),
                        "mapped_file" => p_m.set_mapped_file(v),
                        "writeback" => p_m.set_writeback(v),
                        "pg_pg_in" => p_m.set_pg_pg_in(v),
                        "pg_pg_out" => p_m.set_pg_pg_out(v),
                        "pg_fault" => p_m.set_pg_fault(v),
                        "pg_maj_fault" => p_m.set_pg_maj_fault(v),
                        "inactive_file" => p_m.set_inactive_file(v),
                        "inactive_anon" => p_m.set_inactive_anon(v),
                        "active_file" => p_m.set_active_file(v),
                        "unevictable" => p_m.set_unevictable(v),
                        "hierarchical_memory_limit" => p_m.set_hierarchical_memory_limit(v),
                        "hierarchical_swap_limit" => p_m.set_hierarchical_swap_limit(v),
                        "total_cache" => p_m.set_total_cache(v),
                        "total_rss" => p_m.set_total_rss(v),
                        "total_mapped_file" => p_m.set_total_mapped_file(v),
                        "total_dirty" => p_m.set_total_dirty(v),

                        "total_pg_pg_in" => p_m.set_total_pg_pg_in(v),
                        "total_pg_pg_out" => p_m.set_total_pg_pg_out(v),
                        "total_pg_fault" => p_m.set_total_pg_fault(v),
                        "total_pg_maj_fault" => p_m.set_total_pg_maj_fault(v),
                        "total_inactive_file" => p_m.set_total_inactive_file(v),
                        "total_inactive_anon" => p_m.set_total_inactive_anon(v),
                        "total_active_file" => p_m.set_total_active_file(v),
                        "total_unevictable" => p_m.set_total_unevictable(v),
                        _ => (),
                    }
                }
                metric.set_memory(p_m);
            }

            if let Some(pid_stats) = cg_stats.pids_stats {
                let mut p_pid = metrics::PidsStat::new();
                p_pid.set_limit(pid_stats.limit);
                p_pid.set_current(pid_stats.current);
                metric.set_pids(p_pid);
            }

            if let Some(blk_stats) = cg_stats.blkio_stats {
                let mut p_blk_stats = metrics::BlkIOStat::new();
                p_blk_stats
                    .set_io_serviced_recursive(copy_blkio_entry(&blk_stats.io_serviced_recursive));
                p_blk_stats.set_io_service_bytes_recursive(copy_blkio_entry(
                    &blk_stats.io_service_bytes_recursive,
                ));
                p_blk_stats
                    .set_io_queued_recursive(copy_blkio_entry(&blk_stats.io_queued_recursive));
                p_blk_stats.set_io_service_time_recursive(copy_blkio_entry(
                    &blk_stats.io_service_time_recursive,
                ));
                p_blk_stats.set_io_wait_time_recursive(copy_blkio_entry(
                    &blk_stats.io_wait_time_recursive,
                ));
                p_blk_stats
                    .set_io_merged_recursive(copy_blkio_entry(&blk_stats.io_merged_recursive));
                p_blk_stats.set_io_time_recursive(copy_blkio_entry(&blk_stats.io_time_recursive));
                p_blk_stats.set_sectors_recursive(copy_blkio_entry(&blk_stats.sectors_recursive));

                metric.set_blkio(p_blk_stats);
            }

            if !cg_stats.hugetlb_stats.is_empty() {
                let mut p_huge = Vec::new();
                for (k, v) in cg_stats.hugetlb_stats {
                    let mut h = metrics::HugetlbStat::new();
                    h.set_pagesize(k);
                    h.set_max(v.max_usage);
                    h.set_usage(v.usage);
                    h.set_failcnt(v.failcnt);
                    p_huge.push(h);
                }
                metric.set_hugetlb(p_huge);
            }
        }

        let net_stats = stats.network_stats;
        if !net_stats.is_empty() {
            let mut p_net = Vec::new();
            for v in net_stats.iter() {
                let mut h = metrics::NetworkStat::new();
                h.set_name(v.name.clone());

                h.set_tx_bytes(v.tx_bytes);
                h.set_tx_packets(v.tx_packets);
                h.set_tx_errors(v.tx_errors);
                h.set_tx_dropped(v.tx_dropped);

                h.set_rx_bytes(v.rx_bytes);
                h.set_rx_packets(v.rx_packets);
                h.set_rx_errors(v.rx_errors);
                h.set_rx_dropped(v.rx_dropped);

                p_net.push(h);
            }
            metric.set_network(p_net);
        }

        StatsInfo {
            value: Some(StatsInfoValue {
                type_url: "io.containerd.cgroups.v1.Metrics".to_string(),
                value: metric.write_to_bytes().unwrap(),
            }),
        }
    }
}

fn metrics_v2(stats: agent::StatsContainerResponse) -> StatsInfo {
    let mut metric = metrics_v2::Metrics::new();

    if let Some(cg_stats) = stats.cgroup_stats {
        if let Some(cpu) = cg_stats.cpu_stats {
            // the agent reports nanoseconds
            let mut p_cpu = metrics_v2::CPUStat::new();
            if let Some(usage) = cpu.cpu_usage {
                p_cpu.set_usage_usec(usage.total_usage / 1000);
                p_cpu.set_user_usec(usage.usage_in_usermode / 1000);
                p_cpu.set_system_usec(usage.usage_in_kernelmode / 1000);
            }
            if let Some(throttle) = cpu.throttling_data {
                p_cpu.set_nr_periods(throttle.periods);
                p_cpu.set_nr_throttled(throttle.throttled_periods);
                p_cpu.set_throttled_usec(throttle.throttled_time / 1000);
            }
            metric.set_cpu(p_cpu);
        }

        if let Some(m_stats) = cg_stats.memory_stats {
            let mut p_m = metrics_v2::MemoryStat::new();
            if let Some(m_data) = m_stats.usage {
                p_m.set_usage(m_data.usage);
                p_m.set_usage_limit(m_data.limit);
                p_m.set_max_usage(m_data.max_usage);
            }
            if let Some(m_data) = m_stats.swap_usage {
                p_m.set_swap_usage(m_data.usage);
                p_m.set_swap_limit(m_data.limit);
                p_m.set_swap_max_usage(m_data.max_usage);
            }

            for (k, v) in m_stats.stats {
                match k.as_str() {
                    "anon" => p_m.set_anon(v),
                    "file" => p_m.set_file(v),
                    "kernel_stack" => p_m.set_kernel_stack(v),
                    "slab" => p_m.set_slab(v),
                    "sock" => p_m.set_sock(v),
                    "shmem" => p_m.set_shmem(v),
                    "file_mapped" => p_m.set_file_mapped(v),
                    "file_dirty" => p_m.set_file_dirty(v),
                    "file_writeback" => p_m.set_file_writeback(v),
                    "anon_thp" => p_m.set_anon_thp(v),
                    "inactive_anon" => p_m.set_inactive_anon(v),
                    "active_anon" => p_m.set_active_anon(v),
                    "inactive_file" => p_m.set_inactive_file(v),
                    "active_file" => p_m.set_active_file(v),
                    "unevictable" => p_m.set_unevictable(v),
                    "slab_reclaimable" => p_m.set_slab_reclaimable(v),
                    "slab_unreclaimable" => p_m.set_slab_unreclaimable(v),
                    "pgfault" => p_m.set_pgfault(v),
                    "pgmajfault" => p_m.set_pgmajfault(v),
                    "workingset_refault" => p_m.set_workingset_refault(v),
                    "workingset_activate" => p_m.set_workingset_activate(v),
                    "workingset_nodereclaim" => p_m.set_workingset_nodereclaim(v),
                    "pgrefill" => p_m.set_pgrefill(v),
                    "pgscan" => p_m.set_pgscan(v),
                    "pgsteal" => p_m.set_pgsteal(v),
                    "pgactivate" => p_m.set_pgactivate(v),
                    "pgdeactivate" => p_m.set_pgdeactivate(v),
                    "pglazyfree" => p_m.set_pglazyfree(v),
                    "pglazyfreed" => p_m.set_pglazyfreed(v),
                    "thp_fault_alloc" => p_m.set_thp_fault_alloc(v),
                    "thp_collapse_alloc" => p_m.set_thp_collapse_alloc(v),
                    _ => (),
                }
            }
            metric.set_memory(p_m);
        }

        if let Some(pid_stats) = cg_stats.pids_stats {
            let mut p_pid = metrics_v2::PidsStat::new();
            p_pid.set_limit(pid_stats.limit);
            p_pid.set_current(pid_stats.current);
            metric.set_pids(p_pid);
        }

        // the agent reports io.stat as one entry per device and op
        if let Some(blk_stats) = cg_stats.blkio_stats {
            let mut usage: Vec<metrics_v2::IOEntry> = Vec::new();
            for e in blk_stats.io_service_bytes_recursive.iter() {
                if usage
                    .last()
                    .is_none_or(|u| (u.major, u.minor) != (e.major, e.minor))
                {
                    let mut entry = metrics_v2::IOEntry::new();
                    entry.set_major(e.major);
                    entry.set_minor(e.minor);
                    usage.push(entry);
                }
                let entry = usage.last_mut().unwrap();
                match e.op.as_str() {
                    "read" => entry.set_rbytes(e.value),
                    "write" => entry.set_wbytes(e.value),
                    "rios" => entry.set_rios(e.value),
                    "wios" => entry.set_wios(e.value),
                    _ => (),
                }
            }
            let mut p_io = metrics_v2::IOStat::new();
            p_io.set_usage(usage);
            metric.set_io(p_io);
        }

        for (k, v) in cg_stats.hugetlb_stats {
            let mut h = metrics_v2::HugeTlbStat::new();
            h.set_pagesize(k);
            h.set_max(v.max_usage);
            h.set_current(v.usage);
            h.set_failcnt(v.failcnt);
            metric.hugetlb.push(h);
        }
    }

    for v in stats.network_stats.iter() {
        let mut h = metrics_v2::NetworkStat::new();
        h.set_name(v.name.clone());

        h.set_tx_bytes(v.tx_bytes);
        h.set_tx_packets(v.tx_packets);
        h.set_tx_errors(v.tx_errors);
        h.set_tx_dropped(v.tx_dropped);

        h.set_rx_bytes(v.rx_bytes);
        h.set_rx_packets(v.rx_packets);
        h.set_rx_errors(v.rx_errors);
        h.set_rx_dropped(v.rx_dropped);

        metric.network.push(h);
    }

    StatsInfo {
        value: Some(StatsInfoValue {
            type_url: "io.containerd.cgroups.v2.Metrics".to_string(),
            value: metric.write_to_bytes().unwrap(),
        }),
    }
}

fn copy_blkio_entry(entry: &[agent::BlkioStatsEntry]) -> Vec<metrics::BlkIOEntry> {
    let mut p_entry = Vec::new();

    for e in entry.iter() {
        let mut blk = metrics::BlkIOEntry::new();
        blk.set_op(e.op.clone());
        blk.set_value(e.value);
        blk.set_major(e.major);
        blk.set_minor(e.minor);

        p_entry.push(blk);
    }

    p_entry
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use agent::types::{
        BlkioStats, CgroupStats, CpuStats, CpuUsage, MemoryData, MemoryStats, PidsStats,
        ThrottlingData,
    };

    use super::*;

    fn blkio(major: u64, op: &str, value: u64) -> agent::BlkioStatsEntry {
        agent::BlkioStatsEntry {
            major,
            minor: 0,
            op: op.to_string(),
            value,
        }
    }

    // a busy user-mode loop in a cgroup v2 guest, plus the v1 keys a v1 guest sends
    fn sample() -> Option<agent::StatsContainerResponse> {
        let stats = [
            ("anon", 600),
            ("file", 200),
            ("inactive_file", 150),
            ("pgfault", 42),
            ("pgmajfault", 3),
            ("rss", 7),
            ("pg_fault", 8),
            ("total_inactive_file", 9),
        ];
        Some(agent::StatsContainerResponse {
            cgroup_stats: Some(CgroupStats {
                cpu_stats: Some(CpuStats {
                    cpu_usage: Some(CpuUsage {
                        total_usage: 153_000_000,
                        percpu_usage: vec![],
                        usage_in_kernelmode: 3_000_000,
                        usage_in_usermode: 150_000_000,
                    }),
                    throttling_data: Some(ThrottlingData {
                        periods: 10,
                        throttled_periods: 2,
                        throttled_time: 5_000,
                    }),
                }),
                memory_stats: Some(MemoryStats {
                    usage: Some(MemoryData {
                        usage: 1000,
                        max_usage: 1500,
                        failcnt: 0,
                        limit: 2000,
                    }),
                    stats: HashMap::from(stats.map(|(k, v)| (k.to_string(), v))),
                    ..Default::default()
                }),
                pids_stats: Some(PidsStats {
                    current: 4,
                    limit: 0,
                }),
                blkio_stats: Some(BlkioStats {
                    io_service_bytes_recursive: vec![
                        blkio(254, "read", 11),
                        blkio(254, "write", 12),
                        blkio(254, "rios", 13),
                        blkio(254, "wios", 14),
                        blkio(254, "dbytes", 15),
                        blkio(259, "read", 21),
                    ],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            network_stats: vec![],
        })
    }

    #[test]
    fn stats_on_cgroup_v2_host_are_v2_metrics() {
        let info = StatsInfo::from_agent(sample(), true).value.unwrap();
        assert_eq!(info.type_url, "io.containerd.cgroups.v2.Metrics");
        let m = metrics_v2::Metrics::parse_from_bytes(&info.value).unwrap();

        assert_eq!(m.cpu.usage_usec, 153_000);
        assert_eq!(m.cpu.user_usec, 150_000);
        assert_eq!(m.cpu.system_usec, 3_000);
        assert_eq!(m.cpu.nr_periods, 10);
        assert_eq!(m.cpu.nr_throttled, 2);
        assert_eq!(m.cpu.throttled_usec, 5);

        assert_eq!(m.memory.usage, 1000);
        assert_eq!(m.memory.usage_limit, 2000);
        assert_eq!(m.memory.max_usage, 1500);
        assert_eq!(m.memory.anon, 600);
        assert_eq!(m.memory.file, 200);
        assert_eq!(m.memory.inactive_file, 150);
        assert_eq!(m.memory.pgfault, 42);
        assert_eq!(m.memory.pgmajfault, 3);

        assert_eq!(m.pids.current, 4);

        let io: Vec<_> =
            m.io.usage
                .iter()
                .map(|e| (e.major, e.rbytes, e.wbytes, e.rios, e.wios))
                .collect();
        assert_eq!(io, [(254, 11, 12, 13, 14), (259, 21, 0, 0, 0)]);
    }

    #[test]
    fn stats_on_cgroup_v1_host_are_v1_metrics() {
        let info = StatsInfo::from_agent(sample(), false).value.unwrap();
        assert_eq!(info.type_url, "io.containerd.cgroups.v1.Metrics");
        let m = metrics::Metrics::parse_from_bytes(&info.value).unwrap();

        assert_eq!(m.cpu.usage.total, 153_000_000);
        assert_eq!(m.cpu.usage.user, 150_000_000);
        assert_eq!(m.cpu.usage.kernel, 3_000_000);
        assert_eq!(m.cpu.throttling.throttled_time, 5_000);
        assert_eq!(m.memory.usage.usage, 1000);
        assert_eq!(m.memory.usage.limit, 2000);
        assert_eq!(m.memory.rss, 7);
        assert_eq!(m.memory.pg_fault, 8);
        assert_eq!(m.memory.total_inactive_file, 9);
        assert_eq!(m.memory.inactive_file, 150);
    }
}
