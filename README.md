# os-zapret2

OPNsense plugin for [zapret2](https://github.com/bol-van/zapret2) — DPI bypass for anti-censorship.

GUI-managed, fail-open, supervised, works on both bare-metal OPNsense and virtualized OPNsense (Proxmox/ESXi/Hyper-V).

## What it does

Many ISPs use Deep Packet Inspection (DPI) to read the SNI field in TLS ClientHello packets and block specific websites. zapret2 defeats this by manipulating outgoing TLS handshakes so the DPI device can't read the SNI, while the destination server still reassembles the connection correctly.

This plugin packages [bol-van/zapret2](https://github.com/bol-van/zapret2) into an OPNsense service with:
- A real `pkg add`-installable package that registers under **Firmware → Plugins**.
- Settings page under **Services → Zapret DPI Bypass**.
- Diagnostics page that runs upstream's `blockcheck2` for you and shows winning strategies for your ISP.
- Auto-start on every reboot once Enable is checked.
- `daemon -r` supervision so a dvtws2 crash auto-restarts within ~1 second.
- A safety watchdog that auto-stops the service if a misconfigured strategy starts breaking general HTTPS — your household internet recovers in ~3 minutes without anyone touching anything.
- **`ipfw divert` + `--sockarg` loop-guard** — matches upstream zapret's pfSense init script. An `ipfw divert` rule with `not diverted not sockarg xmit <wan>` intercepts outbound TCP on the configured ports; dvtws2 is launched with `--sockarg=0x200` so its reinjected packets sail past the rule. Combined with the upstream recipe's `pfctl -d; pfctl -e` pfil-hook reorder, this works on both bare-metal PPPoE and virtualized OPNsense (Proxmox/virtio), for both firewall-local traffic and NAT'd LAN clients. (Earlier `pf divert-to`–based 1.6.x releases broke LAN-NAT'd traffic; v1.6.5_3 reverted to the upstream ipfw recipe.)

## Requirements

- OPNsense 26.1 or later. Releases ship one package per FreeBSD major version: `-freebsd14` for OPNsense 26.1–26.4 (FreeBSD 14.x core) and `-freebsd15` for OPNsense 26.7+ (FreeBSD 15.x core). Check yours with `uname -r`.
- Any WAN type — PPPoE, DHCP, static, all work.
- The plugin's `setup.sh` will install `luajit`, `jq`, `git-lite` or `git`, and `pkgconf` from FreeBSD's main repo and compile `dvtws2`. Internet access required for the one-time setup.

## Installation

Releases ship as a real FreeBSD `.pkg`. Install with `pkg add` — OPNsense registers it like any other plugin.

```sh
# On the OPNsense firewall (SSH as root)

# Use -freebsd15 instead of -freebsd14 on OPNsense 26.7+ (uname -r says 15.x)
fetch -o /tmp/os-zapret2.pkg \
    https://github.com/ugorur/os-zapret2/releases/latest/download/os-zapret2-1.8.1-freebsd14.pkg
# (asset filename tracks PLUGIN_VERSION_PLUGIN_REVISION from Makefile — check the
#  Releases page for the current version if the URL above 404s)

pkg add /tmp/os-zapret2.pkg

# Bootstrap dependencies and compile dvtws2 (~1 minute, one-time)
/usr/local/opnsense/scripts/OPNsense/Zapret/setup.sh
```

> **Why `setup.sh` instead of dependencies?** OPNsense's pkg repository doesn't carry `luajit` / `jq` (those live in FreeBSD's main repo, which OPNsense ships disabled by default). `setup.sh` enables that repo for the duration of the install, fetches the deps, then restores the original repo state. The `.pkg` itself stays clean and rapid to install.

After setup, navigate to **Services → Zapret DPI Bypass → Settings** in the GUI.

Verify the install:

```sh
pkg info os-zapret2
```

The plugin will also appear in **Firmware → Plugins** (as `os-zapret2`) and **System → Services** (as `Zapret2 DPI Bypass`) with start/stop controls.

### Uninstall

```sh
pkg delete os-zapret2
```

`+PRE_DEINSTALL` cleanly stops the service and removes ipfw divert rules before files are deleted. Saved settings in `config.xml` are preserved — reinstalling later picks them up.

### Build from source

```sh
# On a FreeBSD 14 host (or in a FreeBSD VM — CI uses vmactions/freebsd-vm)
git clone https://github.com/ugorur/os-zapret2.git
cd os-zapret2
pkg install -y jq
sh scripts/build-pkg.sh
# Output: dist/os-zapret2-<version>.pkg
```

## Additional UDP profile

The Settings page can optionally divert one additional set of UDP ports or ranges to a separate zapret2 profile. This is intended for traffic such as Discord voice, where the transport ports and L7 filter differ from QUIC/UDP 443.

- **Additional UDP Ports** accepts comma-separated numeric ports or ranges, for example `19294-19344,50000-50100`. Only numeric values from 1 to 65535 are accepted; ranges must be ascending; at most 30 entries are allowed by FreeBSD `ipfw`.
- **Additional UDP L7 Protocol Filter** accepts zapret2 protocol names: `discord`, `stun`, `wireguard`, `dht`, `quic`, `unknown`. For Discord voice, `discord,stun` is a reasonable starting filter, not a guaranteed working strategy.
- **Additional UDP Strategy** accepts only `--payload=...`, `--lua-desync=...`, and optional `--out-range=...` arguments. Use syntax verified against the exact installed zapret2 build; general shell syntax, paths, and arbitrary dvtws2 flags are intentionally not accepted by this field.
- All three additional UDP fields must be configured together. Leaving all three empty preserves the current UDP behavior. If any QUIC profile is enabled, the custom port list may not contain port 443.
- Hostname hostlists are attached only when the additional UDP L7 filter is exactly `quic`. Discord Voice/STUN, WireGuard, DHT, and unknown UDP flows generally have no hostname to match, so those profiles omit hostname hostlists and can instead be scoped using IPSet include/exclude filters. The dedicated Discord hostname list applies to the Discord TCP profile, not the UDP voice profile. Source Networks and WAN interface matching are applied to the corresponding `ipfw divert` rule.

This feature adds one firewall rule for the entire additional port list, not one rule per port or range. The rule remains within the plugin's reserved range (19000–19010). This does not by itself prove a supplied desynchronization strategy is effective; test first on a non-critical OPNsense instance or during a maintenance window.

## IPSet include and exclude filters

The Settings page can optionally pass zapret2 `--ipset=` and `--ipset-exclude=` filters to every configured profile. Files must contain one IPv4/IPv6 address or CIDR per line. Blank lines and comments beginning with `#` are ignored. The plugin validates the file before installing divert rules, rejects unsafe filenames, malformed CIDRs, missing/empty files, and files larger than 10 MiB or 100,000 entries.

- **Include filter** restricts bypass processing to destination IP addresses contained in the selected file. For the legacy list, copy the list you intend to use to `/usr/local/etc/zapret2/ipset-all.txt`, then enable the filter and keep the filename as `ipset-all.txt`.
- **Exclude filter** skips destination IP addresses contained in the selected file. The plugin provides `ipset-exclude-default.txt` with common local/private, link-local, multicast, and carrier-grade NAT ranges. To use your own legacy exclude list, copy it to `/usr/local/etc/zapret2/ipset-exclude.txt`, then select that filename in Settings.
- Filenames must be simple names inside `/usr/local/etc/zapret2/`; directory paths and `..` traversal are rejected. Both switches default to off so existing installations keep their prior behavior.

An include IPSet can change which CDN addresses are processed and therefore should be enabled only after confirming that the list is appropriate for the intended services.

## Managed service profiles

The Settings page also exposes opt-in, service-specific profiles. They are placed before the general fallback profiles so a matching connection receives the intended strategy.

- **YouTube / Google TCP** matches the bundled hostlist on TCP/443 with the TLS L7 filter. **YouTube / Google QUIC** matches the same hostlist on UDP/443. The two profiles have independent enable switches and strategy fields.
- **Discord TCP** matches the bundled Discord hostlist on TCP ports `443,2053,2083,2087,2096,8443`. Enabling it also adds those ports to the `ipfw divert` interception list automatically; the generic Ports field does not have to be edited manually.
- **Discord voice / additional UDP** uses Additional UDP Ports plus the UDP L7 filter and a strategy. A commonly used starting port list is `19294-19344,50000-50100`, with `discord,stun` as the L7 filter. This is only a profile/filter starting point; strategy effectiveness depends on the ISP and the exact zapret2 build.

Managed-profile strategy fields accept verified `--payload=...`, `--lua-desync=...`, and optional `--out-range=...` tokens. Do not paste a full BAT line, classic zapret flags such as `--dpi-desync`, shell syntax, or `--new`/filter/hostlist flags into a strategy field. The plugin generates profile boundaries and filter flags itself.

The bundled YouTube/Google and Discord lists are based on the supplied legacy lists. Two separate checkboxes optionally import the supplied general and exclusion domain lists into the generic hostlist templates. Both are off by default, so the old generic hostlist behavior does not change unless enabled. Extra domain fields append entries to the corresponding managed service list.

## Custom profiles (advanced)

Settings includes an optional JSON editor for up to eight custom zapret2 profiles. Leave the value as `[]` to keep the existing built-in profile behavior. Profiles are applied in ascending `order`, before the named YouTube/Google and Discord profiles and before the generic fallbacks. The service validates the complete JSON document and profile fields before adding interception rules; the JSON is rendered to a separate file and is never sourced as shell configuration.

Example:

```json
[
  {
    "enabled": true,
    "name": "discord-voice",
    "order": 10,
    "transport": "udp",
    "ports": "19294-19344,50000-50100",
    "l7": ["discord", "stun"],
    "domains": [],
    "exclude_domains": [],
    "ipset": "inherit",
    "strategy": "--payload=stun,discord_ip_discovery --lua-desync=fake:blob=fake_default_quic:repeats=6"
  },
  {
    "enabled": true,
    "name": "private-tls",
    "order": 20,
    "transport": "tcp",
    "ports": "443,8443",
    "l7": ["tls"],
    "domains": ["example.com", "^exact.example"],
    "exclude_domains": ["bank.example"],
    "ipset": "inherit",
    "strategy": "--payload=tls_client_hello --lua-desync=fake:repeats=2"
  }
]
```

- `enabled` is a JSON boolean; `name` contains only letters, numbers, hyphens, or underscores. Names and integer `order` values must be unique. At most eight profile objects and 64 KiB of JSON are accepted.
- `transport` is `tcp` or `udp`. `ports` accepts comma-separated numbers/ranges from 1 to 65535, with ascending ranges and at most 30 entries per profile. Enabled TCP profile ports are added to the interception rules. All built-in and custom UDP ports are combined into one validated WAN-scoped divert rule, while the dvtws2 profiles retain their own filters.
- `l7` is an array of protocol names. TCP accepts `http`, `tls`, or `unknown`; UDP accepts `quic`, `wireguard`, `dht`, `discord`, `stun`, or `unknown`.
- `domains` and `exclude_domains` are optional hostname arrays. They are allowed for TCP profiles and pure-QUIC UDP profiles only. Non-QUIC UDP flows usually cannot provide a hostname, so use IPSet filters to scope Discord Voice/STUN or other UDP profiles.
- `ipset` defaults to `inherit`; other values are `none`, `include`, `exclude`, or `both`. Selecting `include`, `exclude`, or `both` requires the corresponding global IPSet filter to be enabled and validated.
- `strategy` accepts only verified `--payload=...`, `--lua-desync=...`, and optional `--out-range=...` tokens. Do not use classic zapret flags, arbitrary dvtws2 flags, file paths, shell operators, quotes, or command substitutions.

Custom domain and exclusion lists are written only to the plugin-owned `/usr/local/etc/zapret2/custom-hostlists/` directory. Service stop removes these generated files. The UDP interception list is aggregated to one ipfw rule; the overall TCP rule count still must fit the plugin's reserved rule range `19000–19010`. Test custom strategies on a non-critical firewall before production use.

The legacy IPSet include list is not bundled automatically. The active `ipset-all.txt` supplied in the old configuration contained only `203.0.113.113/32`, a documentation-only address, so it must **not** be used as the active include list. Copy the valid `ipset-all.txt.backup` to `/usr/local/etc/zapret2/ipset-all.txt` on OPNsense before enabling the include filter. The service validates its CIDR syntax before applying it. The legacy exclude IPSet can be uploaded separately and selected by filename; otherwise the bundled local/private-range exclusion file is available.

## Quick start

1. **Services → Zapret DPI Bypass → Diagnostics → Blockcheck.** Enter a domain that's blocked on your ISP (e.g., `rutracker.org`, or any site you can't reach). Click **Run**. Wait 1–3 minutes — the plugin runs upstream's `blockcheck2` against ~50 strategies and reports the winning ones.
2. Copy the strategy with a working result.
3. **Services → Zapret DPI Bypass → Settings.** Tick **Enable**, pick your **WAN Interface** from the dropdown, paste the winning strategy into **HTTPS Strategy**, click **Save & Apply**.
4. Test the same blocked domain from a LAN device — should now load.

## How it works

```
LAN client ──► OPNsense (ipfw divert) ──► dvtws2 (manipulates TLS ClientHello) ──► WAN ──► ISP DPI ──► destination
```

1. Two `ipfw` divert rules (one per configured port, default 80 and 443) match outbound TCP on the WAN device and divert it to a local divert socket on port `989`. The filter `not diverted not sockarg` skips any packet already tagged by the divert path.
2. `dvtws2` reads the diverted packets, applies the LUA-driven desync strategy you configured, and reinjects — marking its reinjects with `SO_USER_COOKIE=0x200` (via `--sockarg=0x200`) so the `not sockarg` clause above skips them on the way back out.
3. On boot/start the plugin also runs `pfctl -d; pfctl -e` once, so pf re-registers its `pfil` hooks **after** `ipfw` — without this reorder pf would drop the reinjected packets for state mismatch on FreeBSD 13+.
4. Reinjected packets go out the WAN. The ISP's DPI sees a TLS ClientHello it can't parse, so it doesn't match the blocklist.
5. The destination server's TLS stack is more lenient than the DPI's, so it reassembles the modified packets and the connection completes normally.

The `ipfw` rules live in the reserved range 19000-19010 and are reinstalled on every `configctl zapret start`, so a config reload (OPNsense save) rebuilds them cleanly.

## Safety

- **`daemon -r` supervision.** If dvtws2 dies, `daemon(8)` auto-restarts it within ~1 second — only a few in-flight packets get dropped by the unhandled divert socket during the restart window.
- **Watchdog auto-stop.** Every minute, a watchdog probes `https://example.com` through the bypass. If 3 consecutive checks fail (= a misconfigured strategy is breaking general HTTPS, or dvtws2 genuinely won't stay up), the watchdog calls `configctl zapret stop` itself. That removes the `ipfw` divert rules and traffic flows through unbypassed again; full recovery in ~3 minutes without anyone touching anything. Check `tail /var/log/messages | grep zapret-watchdog` for the reason. Override the probe URL via `/usr/local/etc/zapret2/watchdog.conf` (`CONTROL_URL=https://...`).
- **No DNS changes required.** The plugin operates at the packet level; your DNS configuration is independent. (For ISP DNS poisoning, pair this with AdGuard/Unbound DoH, which OPNsense supports natively.)
- **WAN-only.** The `ipfw` rules are scoped with `xmit <wan_dev>`; LAN-to-LAN traffic and other interfaces are untouched.

## Troubleshooting

**General HTTPS broke after I clicked Save.** The strategy you picked is too aggressive. Wait ~3 minutes for the watchdog to auto-stop the service, OR click **Stop** in the GUI manually. Re-run **Diagnostics → Blockcheck** to find a milder strategy.

**Bypass works for me on the firewall but not from LAN devices.** The shipped ipfw-divert architecture (v1.6.5_3+) handles NAT'd LAN traffic identically to firewall-local traffic — if you see this, most likely cause is (a) **Host List Mode** set to `Only specific domains` with the target site not listed, or (b) LAN clients using their own DNS (not the OPNsense resolver) so an upstream DNS-level block is still in effect. Check `ipfw list 19000 19001` on the firewall — if the packet counters increment when you curl the blocked site from the LAN, the divert is firing and the issue is elsewhere.

**Service won't start — "dvtws2 child failed to start".** Run `setup.sh` again — the binary may not have compiled. Check `ls /usr/local/etc/zapret2/binaries/my/dvtws2`. If missing, `cd /usr/local/etc/zapret2 && make`.

**Bypass auto-stops repeatedly.** The watchdog is doing its job — your strategy is dropping general HTTPS. Either find a different strategy via Blockcheck or switch **Host List Mode** to `Only specific domains` and list just the censored sites.

## License

MIT — same as [bol-van/zapret2](https://github.com/bol-van/zapret2).

## Credits

- [bol-van/zapret2](https://github.com/bol-van/zapret2) — the underlying DPI bypass tool and lua strategy engine.
- [OPNsense](https://opnsense.org/) — the firewall platform.
- [lexiforest/curl-impersonate](https://github.com/lexiforest/curl-impersonate) — the bundled HTTP/3 client used for QUIC blockcheck.
- [apfilipp](https://github.com/apfilipp) — asynchronous Blockcheck, QUIC/HTTP-3 support, firewall self-repair, and the per-strategy stability test (most of v1.8.3).

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.
