//! Runtime policy for the optional kernel-TLS transport.
//!
//! `auto` is intentionally conservative: it enables kTLS only when the default
//! route resolves to a physical NIC whose ethtool feature table reports an
//! active `tls-hw-tx-offload`. Unknown topology or probe errors stay on rustls.

use std::io;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum KtlsMode {
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Decision {
    pub(crate) enabled: bool,
    pub(crate) reason: String,
    pub(crate) interface: Option<String>,
    pub(crate) driver: Option<String>,
}

trait Probe {
    fn default_interface(&self) -> io::Result<String>;
    fn driver(&self, interface: &str) -> io::Result<String>;
    fn feature_active(&self, interface: &str, feature: &str) -> io::Result<bool>;
}

pub(crate) fn resolve(mode: KtlsMode) -> anyhow::Result<Decision> {
    resolve_with(mode, cfg!(feature = "ktls"), &SystemProbe)
}

fn resolve_with(mode: KtlsMode, compiled: bool, probe: &impl Probe) -> anyhow::Result<Decision> {
    match mode {
        KtlsMode::Off => Ok(disabled("disabled by --ktls=off", None, None)),
        KtlsMode::On if !compiled => {
            anyhow::bail!("--ktls=on requires a `--features ktls` build")
        }
        KtlsMode::On => Ok(Decision {
            enabled: true,
            reason: "forced by --ktls=on; hardware offload was not required".into(),
            interface: None,
            driver: None,
        }),
        KtlsMode::Auto if !compiled => Ok(disabled(
            "auto-disabled: binary was built without the ktls feature",
            None,
            None,
        )),
        KtlsMode::Auto => {
            let interface = match probe.default_interface() {
                Ok(interface) if interface != "lo" => interface,
                Ok(_) => {
                    return Ok(disabled(
                        "auto-disabled: default route is loopback",
                        Some("lo".into()),
                        None,
                    ));
                }
                Err(error) => {
                    return Ok(disabled(
                        format!("auto-disabled: default-route probe failed: {error}"),
                        None,
                        None,
                    ));
                }
            };
            let driver = match probe.driver(&interface) {
                Ok(driver) => driver,
                Err(error) => {
                    return Ok(disabled(
                        format!("auto-disabled: driver probe failed: {error}"),
                        Some(interface),
                        None,
                    ));
                }
            };
            if virtual_driver(&driver) {
                return Ok(disabled(
                    format!("auto-disabled: virtual NIC driver {driver}"),
                    Some(interface),
                    Some(driver),
                ));
            }
            match probe.feature_active(&interface, "tls-hw-tx-offload") {
                Ok(true) => Ok(Decision {
                    enabled: true,
                    reason: "auto-enabled: active NIC TLS transmit offload".into(),
                    interface: Some(interface),
                    driver: Some(driver),
                }),
                Ok(false) => Ok(disabled(
                    "auto-disabled: tls-hw-tx-offload is not active",
                    Some(interface),
                    Some(driver),
                )),
                Err(error) => Ok(disabled(
                    format!("auto-disabled: ethtool feature probe failed: {error}"),
                    Some(interface),
                    Some(driver),
                )),
            }
        }
    }
}

fn disabled(
    reason: impl Into<String>,
    interface: Option<String>,
    driver: Option<String>,
) -> Decision {
    Decision {
        enabled: false,
        reason: reason.into(),
        interface,
        driver,
    }
}

fn virtual_driver(driver: &str) -> bool {
    let driver = driver.to_ascii_lowercase();
    ["gve", "virtio", "veth", "xen", "hv_netvsc", "tun", "tap"]
        .iter()
        .any(|needle| driver.contains(needle))
}

struct SystemProbe;

impl Probe for SystemProbe {
    fn default_interface(&self) -> io::Result<String> {
        let routes = std::fs::read_to_string("/proc/net/route")?;
        routes
            .lines()
            .skip(1)
            .filter_map(|line| {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                if fields.len() < 8 || fields[1] != "00000000" {
                    return None;
                }
                let flags = u16::from_str_radix(fields[3], 16).ok()?;
                if flags & 1 == 0 {
                    return None;
                }
                let metric = fields[6].parse::<u64>().unwrap_or(u64::MAX);
                Some((metric, fields[0].to_owned()))
            })
            .min_by_key(|(metric, _)| *metric)
            .map(|(_, interface)| interface)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 default route"))
    }

    fn driver(&self, interface: &str) -> io::Result<String> {
        #[repr(C)]
        struct DriverInfo {
            cmd: u32,
            driver: [libc::c_char; 32],
            version: [libc::c_char; 32],
            fw_version: [libc::c_char; 32],
            bus_info: [libc::c_char; 32],
            erom_version: [libc::c_char; 32],
            reserved2: [libc::c_char; 12],
            n_priv_flags: u32,
            n_stats: u32,
            testinfo_len: u32,
            eedump_len: u32,
            regdump_len: u32,
        }
        let mut info: DriverInfo = unsafe { std::mem::zeroed() };
        info.cmd = ETHTOOL_GDRVINFO;
        ethtool_ioctl(interface, (&mut info as *mut DriverInfo).cast())?;
        c_chars(&info.driver)
    }

    fn feature_active(&self, interface: &str, feature: &str) -> io::Result<bool> {
        #[repr(C)]
        struct SsetInfo {
            cmd: u32,
            reserved: u32,
            mask: u64,
            count: u32,
        }
        let mut set = SsetInfo {
            cmd: ETHTOOL_GSSET_INFO,
            reserved: 0,
            mask: 1 << ETH_SS_FEATURES,
            count: 0,
        };
        ethtool_ioctl(interface, (&mut set as *mut SsetInfo).cast())?;
        if set.mask & (1 << ETH_SS_FEATURES) == 0 || set.count == 0 {
            return Ok(false);
        }
        let count = usize::try_from(set.count)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "feature count overflow"))?;
        let strings_len = 12usize
            .checked_add(count.checked_mul(ETH_GSTRING_LEN).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "feature table overflow")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "feature table overflow"))?;
        let mut strings = vec![0u8; strings_len];
        put_u32(&mut strings, 0, ETHTOOL_GSTRINGS);
        put_u32(&mut strings, 4, ETH_SS_FEATURES);
        put_u32(&mut strings, 8, set.count);
        ethtool_ioctl(interface, strings.as_mut_ptr().cast())?;
        let Some(index) = (0..count).find(|index| {
            let start = 12 + index * ETH_GSTRING_LEN;
            nul_str(&strings[start..start + ETH_GSTRING_LEN]) == feature
        }) else {
            return Ok(false);
        };

        let blocks = count.div_ceil(32);
        let features_len = 8usize
            .checked_add(blocks.checked_mul(16).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "feature block overflow")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "feature block overflow"))?;
        let mut features = vec![0u8; features_len];
        put_u32(&mut features, 0, ETHTOOL_GFEATURES);
        put_u32(&mut features, 4, blocks as u32);
        ethtool_ioctl(interface, features.as_mut_ptr().cast())?;
        let block = index / 32;
        let active = get_u32(&features, 8 + block * 16 + 8);
        Ok(active & (1 << (index % 32)) != 0)
    }
}

fn ethtool_ioctl(interface: &str, data: *mut libc::c_void) -> io::Result<()> {
    if interface.is_empty()
        || interface.len() >= libc::IFNAMSIZ
        || interface.as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name",
        ));
    }
    // SAFETY: the socket and ifreq live through ioctl; `data` points at the
    // command-specific writable buffer supplied by the caller.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut request: libc::ifreq = std::mem::zeroed();
        for (slot, byte) in request.ifr_name.iter_mut().zip(interface.bytes()) {
            *slot = byte as libc::c_char;
        }
        request.ifr_ifru.ifru_data = data.cast();
        let result = libc::ioctl(fd, SIOCETHTOOL, &mut request);
        let error = io::Error::last_os_error();
        libc::close(fd);
        if result < 0 { Err(error) } else { Ok(()) }
    }
}

fn c_chars(value: &[libc::c_char]) -> io::Result<String> {
    let bytes: Vec<u8> = value.iter().map(|byte| *byte as u8).collect();
    let value = nul_str(&bytes);
    if value.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty driver name",
        ))
    } else {
        Ok(value.to_owned())
    }
}

fn nul_str(bytes: &[u8]) -> &str {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn get_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(
        buffer[offset..offset + 4]
            .try_into()
            .expect("four-byte field"),
    )
}

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GDRVINFO: u32 = 0x0000_0003;
const ETHTOOL_GSTRINGS: u32 = 0x0000_001b;
const ETHTOOL_GSSET_INFO: u32 = 0x0000_0037;
const ETHTOOL_GFEATURES: u32 = 0x0000_003a;
const ETH_SS_FEATURES: u32 = 4;
const ETH_GSTRING_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProbe {
        interface: io::Result<String>,
        driver: io::Result<String>,
        feature: io::Result<bool>,
    }

    impl Probe for MockProbe {
        fn default_interface(&self) -> io::Result<String> {
            clone_result(&self.interface)
        }
        fn driver(&self, _interface: &str) -> io::Result<String> {
            clone_result(&self.driver)
        }
        fn feature_active(&self, _interface: &str, _feature: &str) -> io::Result<bool> {
            clone_result(&self.feature)
        }
    }

    fn clone_result<T: Clone>(result: &io::Result<T>) -> io::Result<T> {
        result
            .as_ref()
            .map(Clone::clone)
            .map_err(|error| io::Error::new(error.kind(), error.to_string()))
    }

    fn probe(driver: &str, feature: bool) -> MockProbe {
        MockProbe {
            interface: Ok("eth0".into()),
            driver: Ok(driver.into()),
            feature: Ok(feature),
        }
    }

    #[test]
    fn auto_requires_compiled_physical_active_offload() {
        assert!(
            !resolve_with(KtlsMode::Auto, false, &probe("ice", true))
                .unwrap()
                .enabled
        );
        assert!(
            !resolve_with(KtlsMode::Auto, true, &probe("ice", false))
                .unwrap()
                .enabled
        );
        assert!(
            resolve_with(KtlsMode::Auto, true, &probe("ice", true))
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn auto_refuses_virtual_drivers_even_if_the_feature_claims_active() {
        for driver in ["gve", "virtio_net", "veth", "xen-netfront", "hv_netvsc"] {
            let decision = resolve_with(KtlsMode::Auto, true, &probe(driver, true)).unwrap();
            assert!(!decision.enabled, "{driver}");
            assert!(decision.reason.contains("virtual NIC"), "{driver}");
        }
    }

    #[test]
    fn loopback_and_probe_failures_fail_closed() {
        let loopback = MockProbe {
            interface: Ok("lo".into()),
            driver: Ok("loopback".into()),
            feature: Ok(true),
        };
        assert!(
            !resolve_with(KtlsMode::Auto, true, &loopback)
                .unwrap()
                .enabled
        );
        let failed = MockProbe {
            interface: Err(io::Error::new(io::ErrorKind::NotFound, "none")),
            driver: Ok("ice".into()),
            feature: Ok(true),
        };
        assert!(!resolve_with(KtlsMode::Auto, true, &failed).unwrap().enabled);
    }

    #[test]
    fn on_forces_only_a_compiled_binary_and_off_never_enables() {
        assert!(resolve_with(KtlsMode::On, false, &probe("ice", true)).is_err());
        assert!(
            resolve_with(KtlsMode::On, true, &probe("gve", false))
                .unwrap()
                .enabled
        );
        assert!(
            !resolve_with(KtlsMode::Off, true, &probe("ice", true))
                .unwrap()
                .enabled
        );
    }

    #[test]
    fn system_probe_reads_current_host_without_enabling_virtual_gve() {
        let decision = resolve_with(KtlsMode::Auto, true, &SystemProbe).unwrap();
        if decision.driver.as_deref() == Some("gve") {
            assert!(!decision.enabled);
        }
    }
}
