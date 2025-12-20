# DEPRECATED MODULES

Modules removed from NIGHTOWL consolidated platform. These were categorized as "theater" (demonstration/POC only), outdated, or requiring infrastructure beyond scope.

## ICS/SCADA (No Real PLC Access)
| Module | Reason |
|--------|--------|
| scada_attack | Requires actual PLC hardware/network access |
| modbus_attack | Protocol simulation only, no real device interaction |
| siemens_s7 | S7comm implementation incomplete, needs real S7 PLC |
| allen_bradley | EtherNet/IP stub, no CIP implementation |

## Mobile (Outdated Exploits)
| Module | Reason |
|--------|--------|
| android_exploit | Exploits for Android 8-10, landscape changed dramatically |
| ios_exploit | Jailbreak-dependent, iOS 14+ not supported |

## Hardware-Dependent (Physical Access Required)
| Module | Reason |
|--------|--------|
| implant_framework | Requires physical hardware implants |
| uefi_rootkit | Needs firmware access, vendor-specific |
| vsat_exploit | Requires SDR hardware ($10k+), satellite access |
| adsb_spoofing | SDR + antenna, illegal without authorization |
| gps_spoofing | GNSS simulator required, highly illegal |

## Destructive (Liability)
| Module | Reason |
|--------|--------|
| wiper_framework | Too dangerous for inclusion, irreversible |
| wiper | Simplified wiper, same concerns |

## Air-Gap (Physical Proximity)
| Module | Reason |
|--------|--------|
| airgap_framework | Requires physical presence, USB drops |
| usb_propagation | Autorun disabled on modern systems |

## Network Infrastructure (ISP/Telecom Access)
| Module | Reason |
|--------|--------|
| bgp_hijack | Requires BGP peering, ISP-level access |
| ss7_attack | Telecom infrastructure access needed |
| wifi_attack | RF hardware, proximity required |

---

## REBUILD CANDIDATES
These modules have good concepts but weak implementations. Scheduled for rebuild in later tasks:

| Module | Task | Notes |
|--------|------|-------|
| zeroday-framework | Task 3 | Needs real vulnerability discovery |
| spearphish-framework | Task 4 | Needs email infrastructure integration |
| cloud-aws | Task 2 | Verify API functionality |
| cloud-azure | Task 2 | Verify API functionality |
| cloud-gcp | Task 2 | Verify API functionality |
| supply-chain | Future | Needs practical implementation |
| exfiltration-multi | Task 5 | Stub file, needs full multi-channel |

---

## Source Locations (Pre-Migration)
- Kit modules: `default/mcps/security-assessment/tools/`
- Strix MCPs: `default/mcps/strix-*/`
- Strix protocols: `default/protocols/strix-*.json`

## Migration Date
2024-12-16

## Decision Criteria
1. **Operational**: Real-world functional, network-accessible, software-only
2. **Theater**: Demo/POC, requires unavailable hardware, outdated exploits
3. **Rebuild**: Good concept, weak implementation, scheduled for enhancement
