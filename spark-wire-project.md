# spark-wire: proved network readers in SPARK

*Project document, 21 October 2026. "spark-wire" is a working name, to be
checked before publication.*

> **Status of every claim in this document.**
> - **Measured** (21 October 2026): the size, dependencies and proof
>   configuration of the initial code base, and the Alire index
>   (`alr search --crates`).
> - **[to confirm]**: export control and any statement about third-party
>   infrastructure. Licences and governance are **proposals** for the
>   maintainers to decide.

---

## 1. Summary

spark-wire is a SPARK library of **readers for what arrives from a
network or a capture file**: Ethernet, 802.1Q, ARP, IPv4/UDP, DHCP, DNS,
ICMP, TCP, LLDP/CDP, 802.11 and radiotap, Bluetooth Low Energy
advertising, the TLS ClientHello, the SSH identification line, HTTP/2 and
HPACK, protobuf and gNMI, NETCONF, BER and SNMPv3, pcap, FAT and GPT, and
RPM, Debian and CPE version strings.

Each reader takes a byte array and answers with a record. It is **proved
free of run-time errors** whatever the bytes, with no justification, no
allocation, no exception and no I/O.

The library starts from an **existing code base of 32 units, already
proved**, which its authors contribute: 4,556 specification lines and
8,160 body lines (the sum of §2.1's table). It is not written from
scratch.

Who it is for: network inventory and monitoring tools, intrusion
detection, protocol analysers, firmware for switches, gateways and IoT
devices, and anyone who must read hostile network input in Ada with a
guarantee stronger than tests.

---

## 2. The initial code base (measured)

### 2.1 Units, by family (spec / body lines)

| family | units |
|---|---|
| root | `Wire` 204/213: `Byte`, `Byte_Array (Natural range <>)`, `U16`, `U32`, `Get_U8/U16/LE16/U32`, `Fits`, `Start_Of`, bounded `Text` (64), `Get_MAC`, `Get_IPv4` |
| link and network | `Frame` 295/159, `ARP` 226/87, `ICMP` 182/109, `TCP` 78/206, `Descriptor` 44/122 |
| discovery and services | `DHCP` 117/276, `DNS` 140/212, `DNS.Records` 124/90, `Neighbour` (LLDP, CDP) 218/438 |
| radio | `Radiotap` 76/142, `Dot11` 75/97, `WiFi` 58/68, `BLE` 60/70 |
| application protocols | `TLS` 284/791 (ClientHello), `SSH_Ident` 98/276, `HTTP2` 157/252, `HPACK` 142/441, `HPACK_Tables` 215, `Protobuf` 137/126, `GNMI` 33/55, `Netconf` 65/223, `Markup` 93/261 |
| management | `BER` 166/173, `SNMPv3` 217/309 |
| files | `PCAP` 81/110, `FAT` 253/113, `FAT.Volume` 216/1627, `Partition` 205/427 |
| versions | `Rpm_Version` 78/255, `Dpkg_Version` 72/247, `CPE_Vocab` 147/185 |

### 2.2 Dependencies

```
Frame ─► ARP ◄─ DNS.Records          SNMPv3 ─► BER
GNMI ─► Protobuf                     HPACK ─► HPACK_Tables
Partition ─► FAT                     CPE_Vocab ─► (one dependency to cut, M2)
```

Every other unit depends on the root package alone. **No unit `with`s an
Ada, GNAT, Interfaces or System unit** (measured): the readers are pure
computation over `Byte_Array`. That is the shape of code that runs on a
restricted runtime **[to confirm with a light-runtime build, M2]**.

### 2.3 Cryptography

**No unit implements or calls a cryptographic primitive** (measured).
SNMPv3 *parses* the user-based security model's parameters (engine ID,
boots, time, user name, the authentication and privacy parameter fields)
and only names the algorithms in comments. The TLS reader parses the
ClientHello, which lists cipher suites as numbers. §7.1 examines what that
means for export control.

### 2.4 Proof

Configured at `--level=2 --report=statistics --checks-as-errors=on
--warnings=error`, no timeout set; a deeper pass at `--level=4
--timeout=120` exists. **`pragma Annotate`: zero occurrences**: nothing is
justified, everything is proved.

### 2.5 Tests and fixtures

A single test driver, one `Check` per case, with captures as fixtures:
DHCP, radio management frames, TLS (pcap and pcapng), HTTP/2 frames,
SNMPv3 with DES/MD5, link-local claims and mDNS, a capture of 1,903
damaged frames, FAT and GPT images, a CPE vocabulary.

**Provenance is the first question for publication**: some captures come
from private networks and may carry addresses, names or community strings.
Each fixture needs a provenance line and a scrub before it is published
(§9, M1).

### 2.6 Language

Some files still carry French comments (the root package, BER, DHCP, and
the proof project file). Publication converts them to English.

---

## 3. Why it is worth publishing

### 3.1 For users

- **The only proved dissector library in the Ada ecosystem**: measured in
  the Alire index, no crate parses DHCP, DNS, LLDP/CDP, 802.11, radiotap,
  BLE, SNMP or HTTP/2. Neighbours exist: `enet` (an embedded network
  stack), `ieee_ethernet` (802.3 declarations), `coap_spark` and
  `ccsds_ada` (protocols with SPARK verification), `cbor_ada` (SPARK),
  `protobuf`, `adamodbus` (SPARK-verified Modbus). The SPARK-protocol
  niche is inhabited, and spark-wire would join a community rather than
  start one.
- **A guarantee no C dissector gives**: no input crashes the reader.
- **No runtime, no allocation**: usable in firmware.

### 3.2 For the code itself

1. **Review and inputs no single team produces.** A proved reader is
   correct only as far as its fixtures go: a strict parser wrong in one
   direction passes every refusal test. Users who feed it their own
   traffic find the frame no fixture holds.
2. **Fuzzing at scale, by others**: the companion project Harrow, and
   third-party fuzzing infrastructure **[to confirm whether it accepts
   Ada/GCC projects]**.
3. **Protocols contributed**: mDNS, SSDP, NetBIOS, LLDP-MED, 802.1X/EAPOL,
   MQTT, Modbus, BACnet, OPC UA headers.
4. **A checkable claim**: "these parsers are proved" means something when
   anyone can run `gnatprove` on them.

### 3.3 Costs

1. **Maintenance**: issues, pull requests, releases, a compatibility
   promise. §4's scope bounds it.
2. **Fixture provenance** (§2.5).
3. **Export control** (§7.1).

---

## 4. Scope

### In

The 32 units of §2.1.

### Not in scope

Writers (except where a reader's unit already holds one, like ARP's
request builder), sockets, capture, reassembly across frames, a dissector
framework or plug-in system. The library reads one buffer and answers;
the caller owns everything else.

---

## 5. Design of the library

### 5.1 Packages

```
Wire                         root: Byte, Byte_Array, bounded accessors, text, MAC, IPv4
Wire.Link.Frame              Ethernet II, 802.1Q, LLC/SNAP
Wire.Link.ARP
Wire.Link.Neighbour          LLDP, CDP
Wire.Net.ICMP  Wire.Net.TCP  Wire.Net.Descriptor
Wire.App.DHCP  Wire.App.DNS  Wire.App.DNS.Records
Wire.App.TLS   Wire.App.SSH_Ident  Wire.App.HTTP2  Wire.App.HPACK (+ Tables)
Wire.App.Protobuf  Wire.App.GNMI  Wire.App.Netconf  Wire.App.Markup
Wire.Mgmt.BER  Wire.Mgmt.SNMPv3
Wire.Air.Radiotap  Wire.Air.Dot11  Wire.Air.WiFi  Wire.Air.BLE
Wire.File.PCAP  Wire.File.FAT (+ Volume)  Wire.File.Partition
Wire.Version.RPM  Wire.Version.Dpkg  Wire.Version.CPE
```

The grouping is a proposal; the flat names of the initial code base work
too, at some cost in readability.

### 5.2 The contract every reader keeps

Written down as the library's rules. Each holds in the initial code base
**[to verify unit by unit in M1, with a control]**:

1. **Total**: any `Byte_Array`, any length, any bounds. `'First` need not
   be 0 or 1: Ada slices keep their parent's bounds, and a reader that
   assumes otherwise reads every field one place off.
2. **No allocation, no exception, no I/O, no global state**.
3. **Results point into the input** (spans or bounded copies, `Text` of
   at most 64 characters), so a caller can hold one buffer.
4. **Proved at level 2 with no justification**, and the proof replays in
   CI.
5. **A refusal is a value**, never an exception, and it says which
   check refused when that is cheap.
6. **Every unit has fixtures that must be ACCEPTED**, taken from outside:
   refusal-only fixtures cannot tell a strict parser from a broken one.

A **control** checks each rule mechanically where it can: a `with` of
anything but `Wire.*` refused; `pragma Annotate` refused; a unit without
an accepted-fixture test refused. A rule is only kept when something
refuses its violation.

### 5.3 Runtime profiles

Because nothing `with`s the runtime, the library should build with
GNAT's light or zero-footprint runtime, which makes it usable in firmware.
To measure in M2; if it holds, it is a strong argument for adoption.

### 5.4 Stability

Types and subprogram profiles are stable within a major version. Adding a
field to a result record is a minor version; changing a profile is a
major one. The changelog names every reader that changed and why.

---

## 6. Users and examples

- **A frame classifier**: read a pcap, run each frame through `Frame`, then
  the matching application reader, and print a one-line summary: a
  `tcpdump`-like example in a hundred lines of Ada.
- **A device inventory**: DHCP, LLDP/CDP, mDNS and ARP readers give
  hostnames, vendors, ports and addresses from passive listening.
- **A version matcher**: the RPM and Debian comparators, for matching
  installed packages against vulnerability ranges.
- **Firmware**: the LLDP reader in a switch's management plane, on a light
  runtime.

Each becomes an `examples/` directory with its own README (M5).

---

## 7. Export control, licence and ownership

### 7.1 Export

No unit implements or calls a cryptographic primitive. Two readers parse
protocols that *carry* protected payloads: SNMPv3 (its security
parameters) and TLS (the ClientHello's cipher suite list). Before
publication **[to confirm with the export rules of the publisher's
jurisdiction]**:

1. that a parser of a protocol carrying encrypted payloads is not itself a
   cryptographic item;
2. whether publication as open source ("publicly available") carries its
   own formalities.

### 7.2 Licence

| licence | effect |
|---|---|
| Apache-2.0 | permissive, with a patent grant; companies adopt it; others may close their changes |
| MIT / BSD-2 | permissive, shortest; no patent grant |
| GPL-3.0 with a runtime exception, or LGPL | changes to the library come back; companies are warier |
| MPL-2.0 | file-level copyleft: changes to the readers come back, the user's own code stays theirs |

Recommendation: **Apache-2.0 or MPL-2.0**. Adoption is the main gain
(§3.2), and Apache maximises it. MPL brings fixes back without scaring
users.

### 7.3 Contributions

A Developer Certificate of Origin (signed-off commits) rather than a
contributor licence agreement keeps contributing simple. The copyright
holder is to be named by the publisher.

---

## 8. Roadmap

| milestone | content | done when |
|---|---|---|
| **M0** decisions | the maintainers decide: licence, names (§5.1), the export reading (§7.1) | each written in the repository's `docs/decisions.md` |
| **M1** audit for publication | per unit: the contract of §5.2 verified; comments converted to English; every fixture given a provenance line and scrubbed of private addresses, names and community strings, or replaced by a synthetic one | a control refuses a fixture without provenance; no French comment remains |
| **M2** cut the ties | `CPE_Vocab`'s one outside dependency removed; the root's text and address helpers kept generic; a build with the light runtime | `gnatprove` at level 2 replays from a fresh `obj/` with no justification; the light-runtime build links |
| **M3** the repository | the layout of §10; the test driver; CI on GNAT FSF 13 and 14: build, proof, tests | a stranger's machine replays the proof and the tests from a clone |
| **M4** fuzzing | Harrow targets for every reader, run nightly | the corpus and the results published with the releases |
| **M5** documentation and examples | per-unit pages (what it reads, from which RFC, what it refuses), the contract, how to add a reader, how to report a vulnerability; §6's examples | a new contributor adds a reader following the page alone |
| **M6** publication | Alire crate, release notes, an announcement where the Ada community reads | published; the first outside issue answered |

---

## 9. Governance

- **Maintainers**: the initial authors, with every merge tested and every
  reader proved, no justification.
- **Security reports**: a `SECURITY.md` naming a private channel and a
  response time.
- **Releases**: semantic versions; a proof replay and the full test suite
  for each; the changelog says which readers changed and why.

---

## 10. Repository layout

```
spark-wire/
  alire.toml
  spark_wire.gpr            -- library project with its Prove package
  src/
    wire.ad[sb]
    wire-link-*.ad[sb]  wire-net-*.ad[sb]  wire-app-*.ad[sb]
    wire-mgmt-*.ad[sb]  wire-air-*.ad[sb]  wire-file-*.ad[sb]  wire-version-*.ad[sb]
  tests/
    driver.adb              -- one Check per case
    fixtures/               -- each with PROVENANCE: source, date, scrubbed by whom
  proof/
    replay.sh               -- gnatprove at level 2, statistics kept per release
  fuzz/                     -- Harrow targets
  controls/                 -- the §5.2 rules as checks
  examples/
    classify/  inventory/  versions/  firmware-lldp/
  docs/
    contract.md  units/<unit>.md  adding-a-reader.md  proof.md  decisions.md  SECURITY.md
  LICENSE  NOTICE  CONTRIBUTING.md (DCO)
```

---

## 11. Open questions, collected

1. Licence? (§7.2; recommendation Apache-2.0 or MPL-2.0)
2. Hierarchical names, or the flat names of the initial code base? (§5.1)
3. Export: does publication need formalities in the publisher's
   jurisdiction, and are the SNMPv3 and TLS readers outside the
   cryptography rules? (§7.1)
4. Who is named as the copyright holder? (§7.3)

---

## Appendix A — measurements behind this document

21 October 2026:

```bash
grep -r "Annotate" src/ | wc -l              # 0
grep -h "^with" src/*.ad? | sort -u          # only Wire.* units, for the 32 in scope
alr search --crates | grep -i -E 'dns|dhcp|lldp|snmp|http|802|radiotap|...'
#   -> enet, ieee_ethernet, coap_spark, ccsds_ada, cbor_ada, protobuf, adamodbus;
#      no dissector library
```

The per-unit sizes in §2.1 are `wc -l` of each specification and body.
