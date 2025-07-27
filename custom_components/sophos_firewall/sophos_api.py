# custom_components/sophos_firewall/sophos_api.py
"""Sophos Firewall API client."""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any
import traceback

import aiohttp
from aiohttp import ClientError, ClientTimeout, ClientConnectorError, ClientResponseError

_LOGGER = logging.getLogger(__name__)

class SophosFirewallAPIError(Exception):
    """Exception to indicate a general API error."""

class SophosFirewallAPI:
    """Sophos Firewall API client."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 4444,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the API client."""
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}/webconsole/APIController"
        self._session: aiohttp.ClientSession | None = None
        self.api_format = "FirewallRule"  # Default format, will be auto-detected
        
        _LOGGER.debug("Initialized Sophos API client with URL: %s", self.base_url)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get aiohttp session."""
        if self._session is None:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            timeout = ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=timeout
            )
            _LOGGER.debug("Created new aiohttp session with SSL verify: %s", self.verify_ssl)
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session:
            await self._session.close()
            self._session = None

    def _create_xml_request(self, request_type: str, entity: str = None, action: str = None, name: str = None) -> str:
        """Create XML request for Sophos API."""
        _LOGGER.debug("Creating XML request - Type: %s, Entity: %s, Action: %s, Name: %s", 
                      request_type, entity, action, name)
        
        request = ET.Element("Request")
        
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        if request_type == "get":
            get_elem = ET.SubElement(request, "Get")
            if entity:
                entity_elem = ET.SubElement(get_elem, entity)
                if name:
                    ET.SubElement(entity_elem, "Name").text = name
        elif request_type == "set":
            set_elem = ET.SubElement(request, "Set")
            if entity:
                entity_elem = ET.SubElement(set_elem, entity)
                if name:
                    ET.SubElement(entity_elem, "Name").text = name
                if action:
                    ET.SubElement(entity_elem, "Status").text = action
        
        xml_string = ET.tostring(request, encoding="unicode")
        _LOGGER.debug("Generated XML request: %s", xml_string)
        return xml_string

    async def _detect_api_format(self) -> str:
        """Detect which API format works with this Sophos firewall."""
        _LOGGER.debug("Auto-detecting API format for Sophos firewall")
        
        # Try different API formats in order of preference
        api_formats = [
            "FirewallRule",    # Most common format - confirmed working
            "Policy",          # Alternative
            "Rule",            # Generic
            "SecurityPolicy",  # v17+ - confirmed NOT working
            "System"           # Basic test
        ]
        
        for api_format in api_formats:
            try:
                _LOGGER.debug("Testing API format: %s", api_format)
                xml_request = self._create_xml_request("get", api_format)
                
                # Make request and check for module error in raw response
                session = await self._get_session()
                async with session.post(
                    self.base_url,
                    data={"reqxml": xml_request},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for module invalid error before parsing
                        if 'code="529"' in content and "Input request module is Invalid" in content:
                            _LOGGER.debug("API format %s not supported (module invalid)", api_format)
                            continue
                        
                        # Try to parse and validate
                        try:
                            root = ET.fromstring(content)
                            result = self._parse_xml_response(root)
                            
                            # Check if we got actual data
                            if result.get("rules") is not None:
                                _LOGGER.info("Successfully detected API format: %s with %d rules", 
                                           api_format, len(result["rules"]))
                                return api_format
                        except Exception as e:
                            _LOGGER.debug("Failed to parse response for format %s: %s", api_format, e)
                            continue
                    
            except Exception as e:
                _LOGGER.debug("API format %s failed: %s", api_format, e)
                continue
        
        _LOGGER.error("Could not detect a working API format")
        raise SophosFirewallAPIError("No compatible API format found")

    async def _make_request(self, xml_data: str) -> dict[str, Any]:
        """Make API request to Sophos Firewall."""
        _LOGGER.debug("Making request to: %s", self.base_url)
        session = await self._get_session()
        
        try:
            _LOGGER.debug("Sending POST request with XML data")
            async with session.post(
                self.base_url,
                data={"reqxml": xml_data},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as response:
                _LOGGER.debug("Received response with status: %s", response.status)
                
                if response.status != 200:
                    error_text = await response.text()
                    _LOGGER.error("HTTP error %s: %s", response.status, error_text)
                    raise SophosFirewallAPIError(f"HTTP {response.status}: {error_text}")
                
                content = await response.text()
                _LOGGER.debug("Response content length: %d characters", len(content))
                _LOGGER.debug("Response content (first 500 chars): %s", content[:500])
                
                # Parse XML response
                try:
                    root = ET.fromstring(content)
                    _LOGGER.debug("Successfully parsed XML response")
                    return self._parse_xml_response(root)
                except ET.ParseError as err:
                    _LOGGER.error("XML parsing error: %s", err)
                    _LOGGER.error("Raw response content: %s", content)
                    raise SophosFirewallAPIError(f"XML parsing error: {err}") from err
                
        except ClientConnectorError as err:
            _LOGGER.error("Connection error to %s:%s - %s", self.host, self.port, err)
            raise SophosFirewallAPIError(f"Cannot connect to {self.host}:{self.port} - {err}") from err
        except ClientResponseError as err:
            _LOGGER.error("HTTP response error: %s", err)
            raise SophosFirewallAPIError(f"HTTP error: {err}") from err
        except asyncio.TimeoutError as err:
            _LOGGER.error("Timeout connecting to %s:%s", self.host, self.port)
            raise SophosFirewallAPIError(f"Timeout connecting to {self.host}:{self.port}") from err
        except ClientError as err:
            _LOGGER.error("Client error communicating with Sophos Firewall: %s", err)
            raise SophosFirewallAPIError(f"Communication error: {err}") from err
        except Exception as err:
            _LOGGER.error("Unexpected error: %s", err)
            _LOGGER.error("Full traceback: %s", traceback.format_exc())
            raise SophosFirewallAPIError(f"Unexpected error: {err}") from err

    def _parse_xml_response(self, root: ET.Element) -> dict[str, Any]:
        """Parse XML response from Sophos API."""
        _LOGGER.debug("Parsing XML response")
        result = {}
        
        # Log the raw XML structure for debugging
        _LOGGER.debug("XML Root tag: %s", root.tag)
        _LOGGER.debug("XML Root attributes: %s", root.attrib)
        
        # Capture API version from root attributes
        if not hasattr(self, 'api_version') and root.attrib.get('APIVersion'):
            self.api_version = root.attrib.get('APIVersion')
            _LOGGER.debug("Detected API version: %s", self.api_version)
        
        # Check for login status (both lowercase and uppercase)
        login_status = root.find(".//status")  # lowercase
        if login_status is None:
            login_status = root.find(".//Status")  # uppercase
            
        if login_status is not None:
            _LOGGER.debug("Found login status: %s", login_status.text)
            if login_status.text != "Authentication Successful":
                _LOGGER.error("Authentication failed with status: %s", login_status.text)
                raise SophosFirewallAPIError(f"Authentication failed: {login_status.text}")
        else:
            _LOGGER.warning("No login status found in response")
        
        # Look for any error messages with status codes
        error_elements = root.findall(".//Status[@code]")
        for error_elem in error_elements:
            code = error_elem.get("code")
            message = error_elem.text
            _LOGGER.debug("Found status element with code %s: %s", code, message)
            
            if code == "529":
                # Module invalid error - this API format is not supported
                raise SophosFirewallAPIError(f"API module not supported: {message}")
            elif code and code != "200":
                raise SophosFirewallAPIError(f"API Error {code}: {message}")
        
        # Parse firewall rules
        rules = []
        rule_paths = [".//FirewallRule", ".//SecurityPolicy", ".//Policy", ".//Rule"]
        
        rule_elements = []
        for path in rule_paths:
            elements = root.findall(path)
            if elements:
                _LOGGER.debug("Found %d elements at path: %s", len(elements), path)
                rule_elements = elements
                break
        
        if rule_elements:
            for i, rule_elem in enumerate(rule_elements):
                _LOGGER.debug("Processing rule element %d: %s", i, rule_elem.tag)
                rule = {}
                
                # Store the full XML element for later use in updates
                import copy
                rule["full_xml_data"] = copy.deepcopy(rule_elem)
                
                # Basic rule information
                name_elem = rule_elem.find("Name")
                if name_elem is not None:
                    rule["name"] = name_elem.text
                    _LOGGER.debug("  Rule name: %s", rule["name"])
                
                # Status/enabled field
                status_elem = rule_elem.find("Status")
                if status_elem is not None:
                    rule["enabled"] = status_elem.text == "Enable"
                    _LOGGER.debug("  Rule enabled: %s", rule["enabled"])
                
                # Description
                description_elem = rule_elem.find("Description")
                if description_elem is not None:
                    rule["description"] = description_elem.text or ""
                
                # Policy type
                policy_type_elem = rule_elem.find("PolicyType")
                if policy_type_elem is not None:
                    rule["policy_type"] = policy_type_elem.text
                
                # Action
                action_elem = rule_elem.find(".//Action")
                if action_elem is not None:
                    rule["action"] = action_elem.text
                
                # Source and destination zones
                source_zones = []
                for zone_elem in rule_elem.findall(".//SourceZones/Zone"):
                    if zone_elem.text:
                        source_zones.append(zone_elem.text)
                if source_zones:
                    rule["source_zones"] = ", ".join(source_zones)
                
                dest_zones = []
                for zone_elem in rule_elem.findall(".//DestinationZones/Zone"):
                    if zone_elem.text:
                        dest_zones.append(zone_elem.text)
                if dest_zones:
                    rule["destination_zones"] = ", ".join(dest_zones)
                
                # IP Family
                ip_family_elem = rule_elem.find("IPFamily")
                if ip_family_elem is not None:
                    rule["ip_family"] = ip_family_elem.text
                
                # Position information
                position_elem = rule_elem.find("Position")
                if position_elem is not None:
                    rule["position"] = position_elem.text
                
                # After element for positioning
                after_elem = rule_elem.find("After/Name")
                if after_elem is not None:
                    rule["after_rule"] = after_elem.text
                
                if rule.get("name"):
                    rules.append(rule)
                    _LOGGER.debug("Added rule: %s", rule["name"])
        
        # Parse firewall rule groups
        groups = []
        group_elements = root.findall(".//FirewallRuleGroup")
        
        if group_elements:
            for group_elem in group_elements:
                group = {}
                import copy
                group["full_xml_data"] = copy.deepcopy(group_elem)
                
                name_elem = group_elem.find("Name")
                if name_elem is not None:
                    group["name"] = name_elem.text
                
                description_elem = group_elem.find("Description")
                if description_elem is not None:
                    group["description"] = description_elem.text or ""
                
                policy_type_elem = group_elem.find("Policytype")
                if policy_type_elem is not None:
                    group["policy_type"] = policy_type_elem.text
                
                group["transactionid"] = group_elem.get("transactionid", "")
                
                group_rules = []
                for policy_elem in group_elem.findall(".//SecurityPolicyList/SecurityPolicy"):
                    if policy_elem.text:
                        group_rules.append(policy_elem.text)
                
                group["rules"] = group_rules
                
                if group.get("name"):
                    groups.append(group)

        # Parse interface statistics
        interface_stats = {}
        for stats_elem in root.findall(".//InterfaceStatistics"):
            name_elem = stats_elem.find("Name")
            usage_elem = stats_elem.find("Usage")
            
            if name_elem is not None and usage_elem is not None:
                interface_name = name_elem.text
                try:
                    usage_value = int(usage_elem.text)
                    interface_stats[f"{interface_name}_usage"] = usage_value
                except (ValueError, TypeError):
                    pass
        
        # Parse interface details
        interface_details = {}
        for interface_elem in root.findall(".//Interface"):
            name_elem = interface_elem.find("Name")
            if name_elem is not None:
                interface_name = name_elem.text
                
                status_elem = interface_elem.find("InterfaceStatus")
                if status_elem is not None:
                    interface_details[f"{interface_name}_status"] = status_elem.text
                
                speed_elem = interface_elem.find("Status")
                if speed_elem is not None:
                    interface_details[f"{interface_name}_connection"] = speed_elem.text
                
                ip_elem = interface_elem.find("IPAddress")
                if ip_elem is not None:
                    interface_details[f"{interface_name}_ip"] = ip_elem.text
                
                zone_elem = interface_elem.find("NetworkZone")
                if zone_elem is not None:
                    interface_details[f"{interface_name}_zone"] = zone_elem.text
        
        # Parse zone information
        zones = {}
        zone_count = 0
        
        for zone_elem in root.findall(".//Zone"):
            zone_count += 1
            name_elem = zone_elem.find("Name")
            type_elem = zone_elem.find("Type")
            
            if name_elem is not None:
                zone_name = name_elem.text
                zones[f"zone_{zone_name}_type"] = type_elem.text if type_elem is not None else "Unknown"
                
                https_elem = zone_elem.find(".//HTTPS")
                ssh_elem = zone_elem.find(".//SSH")
                
                if https_elem is not None:
                    zones[f"zone_{zone_name}_https"] = https_elem.text == "Enable"
                if ssh_elem is not None:
                    zones[f"zone_{zone_name}_ssh"] = ssh_elem.text == "Enable"
        
        zones["total_zones"] = zone_count

        # Parse SystemServices data
        system_services = {}
        for service_elem in root.findall(".//SystemServices"):
            services = ['AntiSpam', 'AntiVirus', 'Authentication', 'DHCPServer', 
                       'DNSServer', 'IPS', 'WebProxy', 'WAF', 'DHCPv6Server']
            
            for service in services:
                service_data = service_elem.find(service)
                if service_data is not None:
                    action_elem = service_data.find("Action")
                    status_elem = service_data.find("Status")
                    
                    if action_elem is not None and status_elem is not None:
                        system_services[f"service_{service.lower()}_action"] = action_elem.text
                        system_services[f"service_{service.lower()}_status"] = status_elem.text
                        is_running = status_elem.text == "RUNNING"
                        system_services[f"service_{service.lower()}_running"] = is_running

        # Parse AdminSettings data
        admin_settings = {}
        for admin_elem in root.findall(".//AdminSettings"):
            hostname_elem = admin_elem.find(".//HostName")
            if hostname_elem is not None:
                admin_settings["hostname"] = hostname_elem.text
            
            https_port_elem = admin_elem.find(".//HTTPSport")
            if https_port_elem is not None:
                admin_settings["https_port"] = https_port_elem.text
            
            logout_elem = admin_elem.find(".//LogoutSession")
            if logout_elem is not None:
                admin_settings["logout_timeout"] = int(logout_elem.text) if logout_elem.text.isdigit() else None
            
            block_login_elem = admin_elem.find(".//BlockLogin")
            if block_login_elem is not None:
                admin_settings["block_login_enabled"] = block_login_elem.text == "Enable"

        # Parse BackupRestore data
        backup_info = {}
        for backup_elem in root.findall(".//BackupRestore"):
            schedule_elem = backup_elem.find("ScheduleBackup")
            if schedule_elem is not None:
                backup_mode_elem = schedule_elem.find("BackupMode")
                freq_elem = schedule_elem.find("BackupFrequency")
                email_elem = schedule_elem.find("EmailAddress")
                
                if backup_mode_elem is not None:
                    backup_info["backup_mode"] = backup_mode_elem.text
                if freq_elem is not None:
                    backup_info["backup_frequency"] = freq_elem.text
                if email_elem is not None:
                    backup_info["backup_email"] = email_elem.text

        # Parse ATP data
        atp_status = {}
        for atp_elem in root.findall(".//ATP"):
            threat_elem = atp_elem.find("ThreatProtectionStatus")
            if threat_elem is not None:
                atp_status["atp_enabled"] = threat_elem.text == "Enable"
            
            inspect_elem = atp_elem.find("InspectContent")
            if inspect_elem is not None:
                atp_status["atp_inspect_content"] = inspect_elem.text

        # Parse PatternDownload data
        pattern_info = {}
        for pattern_elem in root.findall(".//PatternDownload"):
            auto_elem = pattern_elem.find("AutoUpdate")
            interval_elem = pattern_elem.find("Interval")
            
            if auto_elem is not None:
                pattern_info["auto_update_enabled"] = auto_elem.text == "On"
            if interval_elem is not None:
                pattern_info["update_interval"] = interval_elem.text

        # Parse DHCP data
        dhcp_info = {}
        dhcp_options = root.findall(".//DHCP/DHCPOption")
        dhcp_info["dhcp_options_count"] = len(dhcp_options)

        # Parse DNS data
        dns_info = {}
        for dns_elem in root.findall(".//DNS"):
            ipv4_settings = dns_elem.find("IPv4Settings")
            if ipv4_settings is not None:
                dns1_elem = ipv4_settings.find(".//DNS1")
                dns2_elem = ipv4_settings.find(".//DNS2")
                
                if dns1_elem is not None and dns1_elem.text:
                    dns_info["primary_dns"] = dns1_elem.text
                if dns2_elem is not None and dns2_elem.text:
                    dns_info["secondary_dns"] = dns2_elem.text

        # Parse Time data
        time_info = {}
        for time_elem in root.findall(".//Time"):
            tz_elem = time_elem.find("TimeZone")
            if tz_elem is not None:
                time_info["timezone"] = tz_elem.text

        result["rules"] = rules
        result["groups"] = groups
        result["system_health"] = {**system_services, **admin_settings, **atp_status, **pattern_info}
        result["traffic_stats"] = interface_stats
        result["interface_details"] = interface_details
        result["zones"] = zones
        result["backup_info"] = backup_info
        result["dhcp_info"] = dhcp_info
        result["dns_info"] = dns_info
        result["time_info"] = time_info
        
        return result

    async def test_connection(self) -> bool:
        """Test connection to Sophos Firewall."""
        _LOGGER.info("Testing connection to Sophos Firewall at %s:%s", self.host, self.port)
        try:
            self.api_format = await self._detect_api_format()
            _LOGGER.info("Connection test successful! Using API format: %s", self.api_format)
            return True
        except SophosFirewallAPIError as e:
            _LOGGER.error("Sophos API error during connection test: %s", e)
            raise
        except Exception as err:
            _LOGGER.error("Unexpected error during connection test: %s", err)
            raise SophosFirewallAPIError(f"Connection test failed: {err}") from err

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        """Get all firewall rules with group and position information."""
        api_format = getattr(self, 'api_format', 'FirewallRule')
        
        xml_request = self._create_xml_request("get", api_format)
        rules_response = await self._make_request(xml_request)
        
        # Get firewall rule groups
        try:
            groups_xml_request = self._create_xml_request("get", "FirewallRuleGroup")
            groups_response = await self._make_request(groups_xml_request)
            
            rule_to_group_map = {}
            for group in groups_response.get("groups", []):
                group_name = group.get("name", "")
                for rule_name in group.get("rules", []):
                    rule_to_group_map[rule_name] = group_name
            
            for rule in rules_response.get("rules", []):
                rule_name = rule.get("name")
                if rule_name and rule_name in rule_to_group_map:
                    rule["group"] = rule_to_group_map[rule_name]
                    
        except Exception as e:
            _LOGGER.warning("Could not fetch firewall rule groups: %s", e)
        
        return rules_response.get("rules", [])

    async def get_all_monitoring_data(self) -> dict[str, Any]:
        """Get all monitoring data in one call."""
        _LOGGER.debug("Fetching all monitoring data")
        
        rules_data = await self.get_firewall_rules()
        
        monitoring_data = {
            "rules": rules_data,
            "system_health": {},
            "traffic_stats": {}, 
            "interface_details": {},
            "zones": {},
            "backup_info": {},
            "dhcp_info": {},
            "dns_info": {},
            "time_info": {},
        }
        
        # Get additional data from various endpoints
        endpoints_to_try = [
            ("SystemServices", "system_health"),
            ("AdminSettings", "system_health"),
            ("ATP", "system_health"),
            ("PatternDownload", "system_health"),
            ("InterfaceStatistics", "traffic_stats"),
            ("Interface", "interface_details"),
            ("Zone", "zones"),
            ("BackupRestore", "backup_info"),
            ("DHCP", "dhcp_info"),
            ("DNS", "dns_info"),
            ("Time", "time_info"),
        ]
        
        for endpoint, data_key in endpoints_to_try:
            try:
                xml_request = self._create_xml_request("get", endpoint)
                response = await self._make_request(xml_request)
                
                if data_key == "system_health":
                    current_data = monitoring_data[data_key]
                    current_data.update(response.get(data_key, {}))
                else:
                    monitoring_data[data_key] = response.get(data_key, {})
                    
            except Exception as e:
                _LOGGER.debug("Could not get %s: %s", endpoint, e)
        
        return monitoring_data

    async def set_rule_status(self, rule_name: str, enabled: bool) -> bool:
        """Enable or disable a firewall rule while preserving order and group membership."""
        try:
            current_rules = await self.get_firewall_rules()
            
            target_rule = None
            for rule in current_rules:
                if rule["name"] == rule_name:
                    target_rule = rule
                    break
            
            if not target_rule:
                _LOGGER.error("Rule '%s' not found", rule_name)
                return False
            
            full_rule_xml = target_rule.get("full_xml_data")
            if not full_rule_xml:
                _LOGGER.error("No full XML data available for rule '%s'", rule_name)
                return False
            
            xml_request = self._create_update_xml_request(rule_name, enabled, full_rule_xml)
            await self._make_request(xml_request)
            
            _LOGGER.info("Successfully updated rule '%s' to %s", rule_name, "enabled" if enabled else "disabled")
            return True
            
        except SophosFirewallAPIError as err:
            _LOGGER.error("Failed to set rule status for %s: %s", rule_name, err)
            return False

    def _create_update_xml_request(self, rule_name: str, enabled: bool, full_rule_data: ET.Element) -> str:
        """Create XML request to update a firewall rule preserving all settings."""
        request = ET.Element("Request")
        
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        set_elem = ET.SubElement(request, "Set")
        set_elem.set("operation", "update")
        
        import copy
        rule_elem = copy.deepcopy(full_rule_data)
        
        status_elem = rule_elem.find("Status")
        if status_elem is not None:
            status_elem.text = "Enable" if enabled else "Disable"
        
        if not rule_elem.get("transactionid"):
            rule_elem.set("transactionid", "")
        
        set_elem.append(rule_elem)
        
        xml_string = ET.tostring(request, encoding="unicode")
        return xml_string