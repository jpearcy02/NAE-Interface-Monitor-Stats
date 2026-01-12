# Silent Endpoint Detector - NAE Agent for ArubaOS-CX

An HPE Aruba Network Analytics Engine (NAE) agent that detects unresponsive endpoints (cameras, IoT devices) on access ports and automatically remediates by cycling Power over Ethernet (PoE).

## Problem Statement

IoT devices like IP cameras can become unresponsive while maintaining link state - the port stays UP but the device stops transmitting meaningful traffic. Traditional link-down monitoring won't catch this condition. This agent monitors actual traffic rates and takes action when they fall below expected thresholds.

## How It Works

### Discovery Phase (at agent initialization)

1. Queries the switch MAC table via REST API for the configured VLAN
2. Filters MAC addresses by OUI (Organizationally Unique Identifier) prefix
3. Identifies which switch ports have matching devices connected
4. Creates per-port traffic monitors for discovered ports

### Monitoring Phase (continuous)

1. Monitors `rx_bytes` rate on each discovered port (sampled every 60 seconds)
2. When traffic falls below the configured threshold, triggers remediation
3. Logs the event and executes PoE power cycle on the affected port
4. Applies per-port cooldown to prevent repeated cycling

### Remediation Action

```
configure
interface <port>
no power-over-ethernet
power-over-ethernet
exit
```

This power cycles the PoE output, forcing the connected device to reboot.

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `CameraOUI` | string | `00:00:00` | Comma-separated MAC OUI prefixes to monitor (e.g., `00:40:8C,AC:CC:8E`) |
| `VideoVLAN` | string | `1` | VLAN ID to search for MAC addresses |
| `TrafficThreshold` | integer | `100` | Bytes/sec below which remediation triggers |
| `CooldownMinutes` | integer | `30` | Minutes to wait before re-remediating the same port |

## Installation

1. Upload `silent_endpoint_detector.py` to your ArubaOS-CX switch via the NAE web interface
2. Create a new agent and select the `silent_endpoint_detector` script
3. Configure parameters:
   - Set `CameraOUI` to your device manufacturer OUI(s)
   - Set `VideoVLAN` to the VLAN where devices are located
   - Adjust `TrafficThreshold` based on expected device traffic
   - Set `CooldownMinutes` based on how quickly devices recover

## Finding OUI Values

The OUI is the first 3 octets (8 characters including colons) of a MAC address. For example:
- MAC `00:40:8C:12:34:56` has OUI `00:40:8c`
- MAC `AC:CC:8E:AB:CD:EF` has OUI `ac:cc:8e`

You can find OUIs by:
1. Checking device documentation
2. Looking up MAC addresses at [IEEE OUI Lookup](https://standards-oui.ieee.org/)
3. Running `show mac-address-table` on the switch

## Example Configuration

For Axis cameras (OUI `AC:CC:8E`) and Hanwha cameras (OUI `00:09:18`) on VLAN 100:

- **CameraOUI**: `AC:CC:8E,00:09:18`
- **VideoVLAN**: `100`
- **TrafficThreshold**: `100` (bytes/sec - adjust based on camera idle traffic)
- **CooldownMinutes**: `30`

## Monitoring

The agent provides:
- **Dashboard Graph**: Real-time traffic rates for all monitored ports
- **Syslog Messages**: Alerts when thresholds are crossed and remediation occurs
- **Agent Variables**:
  - `cooldown_times`: JSON tracking last remediation time per port

### Sample Syslog Output

```
Rate for interface 1/1/19 below threshold
Toggling PoE for interface 1/1/19
Interface 1/1/19 in cooldown, skipping remediation
```

## Limitations

- **Static Port Discovery**: Ports are discovered at agent initialization. If a device is added or moves to a new port, the agent must be restarted to detect it.
- **Single VLAN**: Currently monitors one VLAN at a time
- **Always Remediates**: Unlike VideoCameraMonitor, this script always cycles PoE when threshold is crossed (no enable/disable toggle)

## REST API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `/rest/v10.16/system/vlans/{id}/macs?attributes=&depth=2&selector=status` | MAC table lookup for port discovery |
| `/rest/v10.16/system/interfaces/{port}?attributes=statistics.rx_bytes` | Per-port traffic monitoring |

## Requirements

- ArubaOS-CX switch with NAE support
- REST API access (enabled by default)
- PoE-capable ports (for PoE cycling remediation)

## Based On

This agent is based on the `VideoCameraMonitor` NAE script pattern, with added features:
- Multi-OUI support (comma-separated list)
- Per-port cooldown tracking
- Enhanced logging

## License

```
Copyright 2024 Hewlett Packard Enterprise Development LP

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Version History

| Version | Changes |
|---------|---------|
| 1.0 | Initial release |
| 1.1 | Added multi-OUI support |
| 1.2 | Added per-port cooldown tracking |
