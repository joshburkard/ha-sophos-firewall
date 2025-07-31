# custom_components/sophos_firewall/sophos_api.py
"""Sophos Firewall API client."""
from __future__ import annotations

import asyncio
import logging
import xml.etree.ElementTree as ET
from typing import Any
import traceback
import time
import uuid

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
            _LOGGER.debug("Sending POST request with XML data (length: %d)", len(xml_data))
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
                _LOGGER.debug("Response content (first 1000 chars): %s", content[:1000])
                
                # Check for obvious error indicators in the response
                if 'code="529"' in content and "Input request module is Invalid" in content:
                    _LOGGER.error("API module invalid error in response")
                    raise SophosFirewallAPIError("API module is invalid")
                
                if 'Authentication Failed' in content:
                    _LOGGER.error("Authentication failed")
                    raise SophosFirewallAPIError("Authentication failed")
                
                # Look for error codes in response
                if 'code=' in content and 'code="200"' not in content:
                    _LOGGER.warning("Potential error in response - contains error codes")
                
                # Parse XML response
                try:
                    root = ET.fromstring(content)
                    _LOGGER.debug("Successfully parsed XML response")
                    
                    # Check the parsed response for errors
                    parsed_result = self._parse_xml_response(root)
                    
                    # Log success indicators
                    if "rules" in parsed_result:
                        _LOGGER.debug("Response contains %d rules", len(parsed_result.get("rules", [])))
                    
                    return parsed_result
                    
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
                rule["original_position"] = i  # Store original position for ordering
                
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
        """Enable or disable a firewall rule using the same approach as the working PowerShell script."""
        try:
            _LOGGER.info("Setting rule '%s' status to %s", rule_name, "enabled" if enabled else "disabled")
            
            # Step 1: Get current groups to find which group this rule belongs to
            current_groups = await self.get_firewall_rule_groups()
            
            rule_group = None
            for group in current_groups:
                if rule_name in group.get("rules", []):
                    rule_group = group
                    _LOGGER.info("Rule '%s' is member of group '%s'", rule_name, group.get("name", "Unknown"))
                    break
            
            if not rule_group:
                _LOGGER.info("Rule '%s' is not a member of any group", rule_name)
            
            # Step 2: Get current firewall rules
            current_rules = await self.get_firewall_rules()
            
            if not current_rules:
                _LOGGER.error("No firewall rules found")
                return False
            
            # Find the target rule
            target_rule = None
            for rule in current_rules:
                if rule["name"] == rule_name:
                    target_rule = rule
                    break
            
            if not target_rule:
                _LOGGER.error("Rule '%s' not found in current rules", rule_name)
                return False
            
            target_rule_current_status = target_rule.get("enabled", False)
            _LOGGER.info("Found target rule '%s', current status: %s, changing to: %s", 
                        rule_name, target_rule_current_status, enabled)
            
            # Check if change is actually needed
            if target_rule_current_status == enabled:
                _LOGGER.info("Rule '%s' is already %s, no change needed", 
                           rule_name, "enabled" if enabled else "disabled")
                return True
            
            # Step 3: Update the rule status using PowerShell approach
            success = await self._update_rule_powershell_style(target_rule, enabled)
            if not success:
                _LOGGER.error("Failed to update rule status")
                return False
            
            # Step 4: Restore group assignment if rule was in a group
            if rule_group:
                _LOGGER.info("Restoring group assignment for group '%s'", rule_group.get("name", ""))
                group_success = await self._restore_single_group_powershell_style(rule_group)
                if not group_success:
                    _LOGGER.warning("Rule update succeeded but group assignment restoration failed")
            
            # Step 5: Verify the change was applied
            await asyncio.sleep(2)  # Give firewall time to process
            verification_success = await self._verify_rule_status(rule_name, enabled)
            if not verification_success:
                _LOGGER.error("Rule update verification failed")
                return False
            
            _LOGGER.info("Successfully updated rule '%s' to %s", rule_name, "enabled" if enabled else "disabled")
            return True
            
        except Exception as err:
            _LOGGER.error("Error setting rule status for %s: %s", rule_name, err)
            _LOGGER.error("Full traceback: %s", traceback.format_exc())
            return False

    async def _update_rule_powershell_style(self, rule: dict[str, Any], enabled: bool) -> bool:
        """Update a single rule using the PowerShell script approach."""
        try:
            rule_name = rule["name"]
            _LOGGER.debug("Updating rule '%s' using PowerShell-style approach", rule_name)
            
            # Clone the rule's original XML data
            import copy
            rule_xml = copy.deepcopy(rule["full_xml_data"])
            
            # Update the status in the XML (just like PowerShell does)
            status_elem = rule_xml.find("Status")
            if status_elem is not None:
                old_status = status_elem.text
                new_status = "Enable" if enabled else "Disable"
                status_elem.text = new_status
                _LOGGER.debug("Updated XML status from '%s' to '%s'", old_status, new_status)
            else:
                _LOGGER.error("No Status element found in rule XML")
                return False
            
            # Ensure empty transaction ID (like PowerShell)
            rule_xml.set("transactionid", "")
            
            # Create the XML request using PowerShell approach
            # <Request><Login>...</Login><Set operation="update">COMPLETE_RULE_XML</Set></Request>
            request = ET.Element("Request")
            
            # Login section
            login = ET.SubElement(request, "Login")
            ET.SubElement(login, "Username").text = self.username
            ET.SubElement(login, "Password").text = self.password
            
            # Set section with operation update
            set_elem = ET.SubElement(request, "Set")
            set_elem.set("operation", "update")
            
            # Add the complete rule XML (equivalent to PowerShell's $FirewallRule.OuterXml)
            set_elem.append(rule_xml)
            
            xml_string = ET.tostring(request, encoding="unicode")
            _LOGGER.debug("PowerShell-style update XML (first 1000 chars): %s", xml_string[:1000])
            
            # Make the request
            response = await self._make_request(xml_string)
            _LOGGER.info("Rule update request completed successfully")
            return True
            
        except Exception as e:
            _LOGGER.error("PowerShell-style rule update failed: %s", e)
            return False

    async def _restore_single_group_powershell_style(self, group: dict[str, Any]) -> bool:
        """Restore a single group assignment using PowerShell approach."""
        try:
            group_name = group.get("name", "")
            _LOGGER.debug("Restoring group '%s' using PowerShell-style approach", group_name)
            
            # Create the XML request using PowerShell approach
            # <Request><Login>...</Login><Set><FirewallRuleGroup>GROUP_INNER_XML</FirewallRuleGroup></Set></Request>
            request = ET.Element("Request")
            
            # Login section
            login = ET.SubElement(request, "Login")
            ET.SubElement(login, "Username").text = self.username
            ET.SubElement(login, "Password").text = self.password
            
            # Set section (no operation attribute like PowerShell)
            set_elem = ET.SubElement(request, "Set")
            
            # Create FirewallRuleGroup element and copy the inner XML from original group
            group_elem = ET.SubElement(set_elem, "FirewallRuleGroup")
            
            # Copy the inner structure from the original group (equivalent to PowerShell's InnerXml)
            import copy
            original_group_xml = group["full_xml_data"]
            
            # Copy all child elements from original group
            for child in original_group_xml:
                group_elem.append(copy.deepcopy(child))
            
            xml_string = ET.tostring(request, encoding="unicode")
            _LOGGER.debug("PowerShell-style group restore XML (first 500 chars): %s", xml_string[:500])
            
            # Make the request
            response = await self._make_request(xml_string)
            _LOGGER.info("Group restoration request completed successfully")
            return True
            
        except Exception as e:
            _LOGGER.error("PowerShell-style group restoration failed: %s", e)
            return False

    async def get_firewall_rule_groups(self) -> list[dict[str, Any]]:
        """Get all firewall rule groups separately."""
        try:
            groups_xml_request = self._create_xml_request("get", "FirewallRuleGroup")
            groups_response = await self._make_request(groups_xml_request)
            return groups_response.get("groups", [])
        except Exception as e:
            _LOGGER.warning("Could not fetch firewall rule groups: %s", e)
            return []

    def _create_complete_rules_update_request(self, rules: list[dict[str, Any]]) -> str:
        """Create XML request to update all firewall rules maintaining order."""
        _LOGGER.debug("Creating complete rules update request with %d rules", len(rules))
        
        request = ET.Element("Request")
        
        # Login section
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        # Set section with operation update
        set_elem = ET.SubElement(request, "Set")
        set_elem.set("operation", "update")
        
        # Generate a unique transaction ID for this batch of updates
        transaction_id = f"ha_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        _LOGGER.debug("Using transaction ID: %s", transaction_id)
        
        # Add all rules in order
        for i, rule in enumerate(rules):
            import copy
            rule_elem = copy.deepcopy(rule["full_xml_data"])
            
            # Set the transaction ID
            rule_elem.set("transactionid", transaction_id)
            
            # Set position information to maintain order
            position_elem = rule_elem.find("Position")
            if position_elem is None:
                position_elem = ET.SubElement(rule_elem, "Position")
            position_elem.text = str(i + 1)
            
            # If not the first rule, set the "After" element to maintain order
            if i > 0:
                after_elem = rule_elem.find("After")
                if after_elem is None:
                    after_elem = ET.SubElement(rule_elem, "After")
                
                # Clear existing After/Name if present
                name_elem = after_elem.find("Name")
                if name_elem is None:
                    name_elem = ET.SubElement(after_elem, "Name")
                
                # Set to the name of the previous rule
                previous_rule_name = rules[i-1]["name"]
                name_elem.text = previous_rule_name
            else:
                # First rule - remove any After element
                after_elem = rule_elem.find("After")
                if after_elem is not None:
                    rule_elem.remove(after_elem)
            
            set_elem.append(rule_elem)
            _LOGGER.debug("Added rule %d: %s (enabled: %s)", i+1, rule["name"], rule.get("enabled", False))
        
        xml_string = ET.tostring(request, encoding="unicode")
        _LOGGER.debug("Generated complete rules update XML (length: %d)", len(xml_string))
        return xml_string

    async def _verify_rule_status(self, rule_name: str, expected_enabled: bool) -> bool:
        """Verify that a rule has the expected enabled status."""
        try:
            _LOGGER.debug("Verifying rule '%s' status is %s", rule_name, "enabled" if expected_enabled else "disabled")
            
            # Get fresh rule data
            current_rules = await self.get_firewall_rules()
            
            for rule in current_rules:
                if rule["name"] == rule_name:
                    actual_enabled = rule.get("enabled", False)
                    _LOGGER.info("Rule '%s' verification - Expected: %s, Actual: %s", 
                               rule_name, expected_enabled, actual_enabled)
                    return actual_enabled == expected_enabled
            
            _LOGGER.error("Rule '%s' not found during verification", rule_name)
            return False
            
        except Exception as e:
            _LOGGER.error("Failed to verify rule status: %s", e)
            return False

    async def _restore_group_assignments(self, groups: list[dict[str, Any]], rule_to_group_map: dict) -> bool:
        """Restore firewall rule group assignments after rules have been updated."""
        success_count = 0
        total_groups = len(groups)
        
        _LOGGER.info("Starting group restoration for %d groups", total_groups)
        
        for i, group in enumerate(groups):
            try:
                group_name = group.get("name", "")
                if not group_name:
                    _LOGGER.warning("Group %d has no name, skipping", i)
                    continue
                
                # Get all rules that should be in this group
                rules_for_group = group.get("rules", [])
                if not rules_for_group:
                    _LOGGER.debug("Group '%s' has no rules to assign, skipping", group_name)
                    success_count += 1  # Count as success since there's nothing to do
                    continue
                
                _LOGGER.info("Restoring group '%s' with %d rules: %s", 
                           group_name, len(rules_for_group), ", ".join(rules_for_group))
                
                # Create group reassignment XML request
                xml_request = self._create_group_assignment_request(group, rules_for_group)
                
                # Log the XML for debugging
                _LOGGER.debug("Group assignment XML preview (first 500 chars): %s", xml_request[:500])
                
                response = await self._make_request(xml_request)
                success_count += 1
                _LOGGER.info("Successfully restored group '%s' (%d/%d)", group_name, success_count, total_groups)
                
                # Small delay between group assignments
                if i < len(groups) - 1:  # Don't delay after the last group
                    await asyncio.sleep(1)
                
            except Exception as e:
                _LOGGER.error("Failed to restore group '%s': %s", group.get("name", "Unknown"), e)
                _LOGGER.error("Group restoration error traceback: %s", traceback.format_exc())
        
        _LOGGER.info("Group restoration completed: %d out of %d groups successful", success_count, total_groups)
        return success_count == total_groups

    def _create_group_assignment_request(self, group: dict[str, Any], rule_names: list[str]) -> str:
        """Create XML request to assign rules to a firewall rule group."""
        _LOGGER.debug("Creating group assignment request for '%s' with rules: %s", 
                     group.get("name", ""), rule_names)
        
        request = ET.Element("Request")
        
        # Login section
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        # Set section with operation update
        set_elem = ET.SubElement(request, "Set")
        set_elem.set("operation", "update")
        
        # Create firewall rule group element
        group_elem = ET.SubElement(set_elem, "FirewallRuleGroup")
        
        # Generate a unique transaction ID for this group assignment
        transaction_id = f"grp_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        group_elem.set("transactionid", transaction_id)
        _LOGGER.debug("Using group transaction ID: %s", transaction_id)
        
        # Group name
        name_elem = ET.SubElement(group_elem, "Name")
        name_elem.text = group.get("name", "")
        
        # Description
        desc_elem = ET.SubElement(group_elem, "Description")
        desc_elem.text = group.get("description", "")
        
        # Policy type
        policy_type_elem = ET.SubElement(group_elem, "Policytype")
        policy_type_elem.text = group.get("policy_type", "Any")
        
        # Security policy list with all rules
        policy_list_elem = ET.SubElement(group_elem, "SecurityPolicyList")
        for rule_name in rule_names:
            policy_elem = ET.SubElement(policy_list_elem, "SecurityPolicy")
            policy_elem.text = rule_name
            _LOGGER.debug("Added rule '%s' to group '%s'", rule_name, group.get("name", ""))
        
        xml_string = ET.tostring(request, encoding="unicode")
        _LOGGER.debug("Generated group assignment XML (length: %d)", len(xml_string))
        return xml_string

    def _create_update_xml_request(self, rule_name: str, enabled: bool, full_rule_data: ET.Element) -> str:
        """Create XML request to update a firewall rule preserving all settings.
        
        NOTE: This method is kept for backward compatibility but is not recommended.
        Use set_rule_status() which updates the complete rule set instead.
        """
        _LOGGER.warning("Using deprecated single rule update method. Consider using complete rule set update.")
        
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

    async def update_multiple_rules(self, rule_updates: list[dict[str, Any]]) -> bool:
        """Update multiple firewall rules at once while maintaining order and groups.
        
        Args:
            rule_updates: List of dicts with 'name' and 'enabled' keys
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            _LOGGER.info("Updating %d firewall rules", len(rule_updates))
            
            # Get all current firewall rules and groups
            current_rules = await self.get_firewall_rules()
            current_groups = await self.get_firewall_rule_groups()
            
            if not current_rules:
                _LOGGER.error("No firewall rules found")
                return False
            
            # Store original group assignments for later restoration
            rule_to_group_map = {}
            for group in current_groups:
                group_name = group.get("name", "")
                for rule_name_in_group in group.get("rules", []):
                    rule_to_group_map[rule_name_in_group] = group
            
            # Create a map of rule updates for quick lookup
            updates_map = {update["name"]: update["enabled"] for update in rule_updates}
            
            # Sort rules by original position to maintain order
            current_rules.sort(key=lambda x: x.get("original_position", 0))
            
            # Update rules as needed
            updated_rules = []
            updated_count = 0
            
            for rule in current_rules:
                rule_name = rule["name"]
                
                if rule_name in updates_map:
                    new_enabled_status = updates_map[rule_name]
                    
                    if rule.get("enabled") != new_enabled_status:
                        _LOGGER.debug("Updating rule '%s' from %s to %s", 
                                     rule_name, rule.get("enabled"), new_enabled_status)
                        
                        # Create a copy of the rule with updated status
                        updated_rule = rule.copy()
                        updated_rule["enabled"] = new_enabled_status
                        
                        # Update the XML data
                        import copy
                        updated_xml = copy.deepcopy(rule["full_xml_data"])
                        status_elem = updated_xml.find("Status")
                        if status_elem is not None:
                            status_elem.text = "Enable" if new_enabled_status else "Disable"
                        
                        updated_rule["full_xml_data"] = updated_xml
                        updated_rules.append(updated_rule)
                        updated_count += 1
                    else:
                        updated_rules.append(rule)
                else:
                    updated_rules.append(rule)
            
            if updated_count == 0:
                _LOGGER.info("No rules needed updating")
                return True
            
            # Step 1: Update all rules (this will lose group assignments)
            xml_request = self._create_complete_rules_update_request(updated_rules)
            
            _LOGGER.debug("Step 1: Sending complete rule set update with %d rules (%d updated)", 
                         len(updated_rules), updated_count)
            response = await self._make_request(xml_request)
            
            # Step 2: Restore group assignments for all groups that had rules
            _LOGGER.debug("Step 2: Restoring group assignments for %d groups", len(current_groups))
            success = await self._restore_group_assignments(current_groups, rule_to_group_map)
            
            if not success:
                _LOGGER.warning("Rule updates succeeded but some group assignments may not have been restored")
            
            _LOGGER.info("Successfully updated %d firewall rules", updated_count)
            return True
            
        except SophosFirewallAPIError as err:
            _LOGGER.error("Failed to update multiple rules: %s", err)
            return False
        except Exception as err:
            _LOGGER.error("Unexpected error updating multiple rules: %s", err)
            return False

    async def reorder_firewall_rules(self, ordered_rule_names: list[str]) -> bool:
        """Reorder firewall rules according to the provided list while preserving groups.
        
        Args:
            ordered_rule_names: List of rule names in desired order
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            _LOGGER.info("Reordering %d firewall rules", len(ordered_rule_names))
            
            # Get all current firewall rules and groups
            current_rules = await self.get_firewall_rules()
            current_groups = await self.get_firewall_rule_groups()
            
            if not current_rules:
                _LOGGER.error("No firewall rules found")
                return False
            
            # Store original group assignments for later restoration
            rule_to_group_map = {}
            for group in current_groups:
                group_name = group.get("name", "")
                for rule_name_in_group in group.get("rules", []):
                    rule_to_group_map[rule_name_in_group] = group
            
            # Create a map for quick rule lookup
            rules_map = {rule["name"]: rule for rule in current_rules}
            
            # Check that all requested rules exist
            missing_rules = []
            for rule_name in ordered_rule_names:
                if rule_name not in rules_map:
                    missing_rules.append(rule_name)
            
            if missing_rules:
                _LOGGER.error("Cannot reorder - missing rules: %s", missing_rules)
                return False
            
            # Create new ordered list
            reordered_rules = []
            for rule_name in ordered_rule_names:
                rule = rules_map[rule_name].copy()
                rule["original_position"] = len(reordered_rules)  # Update position
                reordered_rules.append(rule)
            
            # Add any rules not in the ordered list at the end
            for rule in current_rules:
                if rule["name"] not in ordered_rule_names:
                    rule_copy = rule.copy()
                    rule_copy["original_position"] = len(reordered_rules)
                    reordered_rules.append(rule_copy)
            
            # Step 1: Update rule order (this will lose group assignments)
            xml_request = self._create_complete_rules_update_request(reordered_rules)
            
            _LOGGER.debug("Step 1: Sending reordered rule set with %d rules", len(reordered_rules))
            response = await self._make_request(xml_request)
            
            # Step 2: Restore group assignments for all groups that had rules
            _LOGGER.debug("Step 2: Restoring group assignments for %d groups", len(current_groups))
            success = await self._restore_group_assignments(current_groups, rule_to_group_map)
            
            if not success:
                _LOGGER.warning("Rule reordering succeeded but some group assignments may not have been restored")
            
            _LOGGER.info("Successfully reordered firewall rules")
            return True
            
        except SophosFirewallAPIError as err:
            _LOGGER.error("Failed to reorder rules: %s", err)
            return False
        except Exception as err:
            _LOGGER.error("Unexpected error reordering rules: %s", err)
            return False