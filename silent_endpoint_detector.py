# -*- coding: utf-8 -*-
#
# (c) Copyright 2024 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Manifest = {
    'Name': 'silent_endpoint_detector',
    'Description': 'Detects silent endpoints and remediates by cycling PoE.',
    'Version': '1.2',
    'Author': 'HPE Aruba Networking'
}

ParameterDefinitions = {
    'CameraOUI': {
        'Name': 'OUI',
        'Description': 'Comma-separated MAC OUI prefixes to monitor (e.g., 00:40:8C,AC:CC:8E).',
        'Type': 'string',
        'Default': '00:00:00'
    },
    'VideoVLAN': {
        'Name': 'VLAN',
        'Description': 'VLAN ID to monitor for MAC addresses.',
        'Type': 'string',
        'Default': '1'
    },
    'TrafficThreshold': {
        'Name': 'Threshold',
        'Description': 'When traffic (bytes/sec) falls below this value, remediation triggers.',
        'Type': 'integer',
        'Default': 100
    },
    'CooldownMinutes': {
        'Name': 'Cooldown (minutes)',
        'Description': 'Minutes to wait before re-remediating the same port.',
        'Type': 'integer',
        'Default': 30
    }
}

import json
import time
import requests


def parse_oui_list(oui_param):
    """Parse comma-separated OUI list into list of OUI strings (first 8 chars with colons)."""
    if not oui_param:
        return []
    # Split by comma and keep first 8 chars of each (e.g., "00:11:22")
    result = []
    for oui in oui_param.split(','):
        oui = oui.strip()
        if oui:
            # Take first 8 chars to match MAC format "00:11:22"
            result.append(oui[:8].lower())
    return result


def get_interface(event):
    label = event['labels']
    first = '='
    last = ',TimeInterval'
    try:
        start = label.index(first) + len(first)
        end = label.index(last, start)
        return label[start:end]
    except ValueError:
        return ""


class Agent(NAE):

    def __init__(self):
        # Initialize cooldown tracking (stores last remediation time per port)
        if 'cooldown_times' not in self.variables:
            self.variables['cooldown_times'] = '{}'

        # Find ports with devices matching OUI allowlist
        self.port_list = self.find_monitored_ports()

        # Create monitors and rules for each port
        self.monitor_list = []
        for port in self.port_list:
            self.logger.info("Adding monitor for port: {}".format(port))

            # Create monitor - matching VideoCameraMonitor exactly
            uri = '/rest/v10.16/system/interfaces/{}?attributes=statistics.rx_bytes'.format(
                port.replace("/", "%2F")
            )
            m = Monitor(Rate(uri, "60s"), '{} (bytes per second)'.format(port))
            self.monitor_list.append(m)
            setattr(self, port.replace("/", "_") + "_rx_mon", m)

            # Create rule - matching VideoCameraMonitor exactly
            r = Rule("Detect when traffic falls below threshold")
            r.condition("{} < {} pause 1 minute", [getattr(self, port.replace("/", "_") + "_rx_mon"), self.params['TrafficThreshold']])
            r.action(self.alert_action)
            setattr(self, port.replace("/", "_") + "_rule", r)

        # Create graph
        if self.monitor_list:
            self.rx_traffic_graph = Graph(
                self.monitor_list,
                title=Title("Camera Traffic"),
                dashboard_display=True
            )

    def find_monitored_ports(self):
        # Get VLAN - matching VideoCameraMonitor pattern
        monitored_vlan = self.params['VideoVLAN'].value
        if not monitored_vlan or monitored_vlan == '0':
            self.logger.info("No VLAN configured for MAC monitoring")
            return []

        # Get OUI list - matching VideoCameraMonitor pattern
        oui_param = self.params['CameraOUI'].value
        self.logger.info("OUI parameter: {}".format(oui_param))
        oui_list = parse_oui_list(oui_param)
        self.logger.info("Parsed OUI list: {}".format(oui_list))
        if not oui_list:
            self.logger.info("No OUI configured")
            return []

        # Fetch MAC table via REST API
        mac_table_uri = '/rest/v10.16/system/vlans/{}/macs?attributes=&depth=2&selector=status'.format(
            monitored_vlan
        )

        try:
            response = requests.get(
                HTTP_ADDRESS + mac_table_uri,
                verify=False,
                proxies={'http': None, 'https': None}
            )
            mac_table = json.loads(response.text)
            self.logger.debug("MAC table response: {}".format(str(mac_table)[:500]))
        except Exception as e:
            self.logger.warning("Failed to fetch MAC table: {}".format(e))
            return []

        # Find ports with matching MACs - matching VideoCameraMonitor pattern
        result = []
        for entry, info in mac_table.items():
            try:
                if info.get('mac_addr'):
                    mac = str(info['mac_addr'])
                    # Get first 8 chars of MAC (e.g., "00:11:22") - same as VideoCameraMonitor
                    mac_oui = mac[:8].lower()

                    self.logger.debug("MAC {} OUI {} checking against {}".format(mac, mac_oui, oui_list))

                    if mac_oui in oui_list:
                        port_info = info.get('port', {})
                        if port_info:
                            port = str(list(port_info.keys())[0])
                            if port not in result:
                                result.append(port)
                                self.logger.info("Found monitored port {}: MAC {}".format(port, mac))
            except Exception as e:
                self.logger.debug("Error parsing MAC entry {}: {}".format(entry, e))

        self.logger.info("Found {} ports to monitor".format(len(result)))
        return result

    def is_in_cooldown(self, interface):
        """Check if interface is still in cooldown period."""
        try:
            cooldown_times = json.loads(self.variables.get('cooldown_times', '{}'))
        except:
            cooldown_times = {}

        if interface not in cooldown_times:
            return False

        last_remediation = cooldown_times[interface]
        cooldown_seconds = self.params['CooldownMinutes'].value * 60
        elapsed = time.time() - last_remediation

        if elapsed < cooldown_seconds:
            return True
        return False

    def set_cooldown(self, interface):
        """Record remediation time for interface."""
        try:
            cooldown_times = json.loads(self.variables.get('cooldown_times', '{}'))
        except:
            cooldown_times = {}

        cooldown_times[interface] = time.time()
        self.variables['cooldown_times'] = json.dumps(cooldown_times)

    def alert_action(self, event):
        """Action callback when traffic falls below threshold."""
        print("event is {}".format(event))
        interface = get_interface(event)

        if not interface:
            return

        # Check cooldown
        if self.is_in_cooldown(interface):
            self.logger.info("Interface {} in cooldown, skipping remediation".format(interface))
            ActionSyslog("Interface {} in cooldown, skipping remediation".format(interface))
            return

        # Syslog
        ActionSyslog("Rate for interface {} below threshold".format(interface))

        # Collect output
        ActionCLI("show int {}".format(interface))

        # Do recovery
        ActionSyslog('Toggling PoE for interface {}'.format(interface), severity=SYSLOG_WARNING)
        ActionCLI('configure\ninterface ' + interface + '\nno power-over-ethernet\npower-over-ethernet\nexit\n')

        # Set cooldown for this interface
        self.set_cooldown(interface)
        self.logger.info("Interface {} remediated, cooldown started".format(interface))
