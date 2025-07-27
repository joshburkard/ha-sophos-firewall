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
            "FirewallRule",    # Most common format
            "SecurityPolicy",  # v17+
            "Policy",          # Alternative
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
        
        # Parse firewall rules from different possible locations
        rules = []
        
        # Try different rule element names based on Sophos version
        rule_paths = [
            ".//FirewallRule",    # Most common - your firewall uses this
            ".//SecurityPolicy",  # v17+
            ".//Policy",          # Alternative
            ".//Rule"             # Generic
        ]
        
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
                
                # Log all child elements for debugging
                for child in rule_elem:
                    _LOGGER.debug("  Child element: %s = %s", child.tag, child.text)
                
                # Basic rule information - try different field names
                name_elem = rule_elem.find("Name")
                if name_elem is not None:
                    rule["name"] = name_elem.text
                    _LOGGER.debug("  Rule name: %s", rule["name"])
                
                # Status/enabled field
                status_elem = rule_elem.find("Status")
                if status_elem is not None:
                    # Sophos uses "Enable"/"Disable" 
                    rule["enabled"] = status_elem.text == "Enable"
                    _LOGGER.debug("  Rule enabled: %s (from '%s')", rule["enabled"], status_elem.text)
                
                # Description
                description_elem = rule_elem.find("Description")
                if description_elem is not None:
                    rule["description"] = description_elem.text or ""
                
                # Policy type and action - need to look in nested policy elements
                policy_type_elem = rule_elem.find("PolicyType")
                if policy_type_elem is not None:
                    rule["policy_type"] = policy_type_elem.text
                
                # Action is nested in NetworkPolicy or UserPolicy
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
                else:
                    _LOGGER.warning("Skipping rule without name")
        
        # Parse firewall rule groups
        groups = []
        group_elements = root.findall(".//FirewallRuleGroup")
        
        if group_elements:
            _LOGGER.debug("Found %d FirewallRuleGroup elements", len(group_elements))
            
            for i, group_elem in enumerate(group_elements):
                _LOGGER.debug("Processing group element %d: %s", i, group_elem.tag)
                group = {}
                
                # Store the full XML element for later use
                import copy
                group["full_xml_data"] = copy.deepcopy(group_elem)
                
                # Group name
                name_elem = group_elem.find("Name")
                if name_elem is not None:
                    group["name"] = name_elem.text
                    _LOGGER.debug("  Group name: %s", group["name"])
                
                # Group description
                description_elem = group_elem.find("Description")
                if description_elem is not None:
                    group["description"] = description_elem.text or ""
                
                # Policy type
                policy_type_elem = group_elem.find("Policytype")
                if policy_type_elem is not None:
                    group["policy_type"] = policy_type_elem.text
                
                # Transaction ID
                group["transactionid"] = group_elem.get("transactionid", "")
                
                # Rules in this group
                group_rules = []
                for policy_elem in group_elem.findall(".//SecurityPolicyList/SecurityPolicy"):
                    if policy_elem.text:
                        group_rules.append(policy_elem.text)
                        _LOGGER.debug("  Group rule: %s", policy_elem.text)
                
                group["rules"] = group_rules
                
                if group.get("name"):
                    groups.append(group)
                    _LOGGER.debug("Added group: %s with %d rules", group["name"], len(group_rules))
        
        result["rules"] = rules
        result["groups"] = groups
        _LOGGER.debug("Total rules parsed: %d, groups parsed: %d", len(rules), len(groups))
        return result

    async def test_connection(self) -> bool:
        """Test connection to Sophos Firewall."""
        _LOGGER.info("Testing connection to Sophos Firewall at %s:%s", self.host, self.port)
        try:
            # Try to detect the correct API format
            self.api_format = await self._detect_api_format()
            _LOGGER.info("Connection test successful! Using API format: %s", self.api_format)
            return True
            
        except SophosFirewallAPIError as e:
            _LOGGER.error("Sophos API error during connection test: %s", e)
            raise
        except Exception as err:
            _LOGGER.error("Unexpected error during connection test: %s", err)
            _LOGGER.error("Full traceback: %s", traceback.format_exc())
            raise SophosFirewallAPIError(f"Connection test failed: {err}") from err

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        """Get all firewall rules with group and position information."""
        # Use the detected API format or default to FirewallRule
        api_format = getattr(self, 'api_format', 'FirewallRule')
        
        # First get all firewall rules
        xml_request = self._create_xml_request("get", api_format)
        rules_response = await self._make_request(xml_request)
        
        # Then get firewall rule groups to understand group membership
        try:
            groups_xml_request = self._create_xml_request("get", "FirewallRuleGroup")
            groups_response = await self._make_request(groups_xml_request)
            
            # Create a mapping of rules to their groups
            rule_to_group_map = {}
            for group in groups_response.get("groups", []):
                group_name = group.get("name", "")
                for rule_name in group.get("rules", []):
                    rule_to_group_map[rule_name] = group_name
            
            # Add group information to rules
            for rule in rules_response.get("rules", []):
                rule_name = rule.get("name")
                if rule_name and rule_name in rule_to_group_map:
                    rule["group"] = rule_to_group_map[rule_name]
                    
        except Exception as e:
            _LOGGER.warning("Could not fetch firewall rule groups: %s", e)
        
        # Store the full rule data for later use in updates
        self._full_rules_data = {}
        for rule in rules_response.get("rules", []):
            if rule.get("name"):
                self._full_rules_data[rule["name"]] = rule.get("full_xml_data")
        
        return rules_response.get("rules", [])

    async def get_firewall_rule_groups(self) -> list[dict[str, Any]]:
        """Get all firewall rule groups."""
        try:
            xml_request = self._create_xml_request("get", "FirewallRuleGroup")
            response = await self._make_request(xml_request)
            return response.get("groups", [])
        except Exception as e:
            _LOGGER.error("Failed to get firewall rule groups: %s", e)
            return []

    async def set_rule_status(self, rule_name: str, enabled: bool) -> bool:
        """Enable or disable a firewall rule while preserving order and group membership."""
        try:
            # Get the current full rule data and groups
            current_rules = await self.get_firewall_rules()
            current_groups = await self.get_firewall_rule_groups()
            
            target_rule = None
            for rule in current_rules:
                if rule["name"] == rule_name:
                    target_rule = rule
                    break
            
            if not target_rule:
                _LOGGER.error("Rule '%s' not found", rule_name)
                return False
            
            # Get the full XML data for this rule
            full_rule_xml = target_rule.get("full_xml_data")
            if not full_rule_xml:
                _LOGGER.error("No full XML data available for rule '%s'", rule_name)
                return False
            
            # Check if rule is in a group and preserve group membership
            rule_group = target_rule.get("group")
            if rule_group:
                _LOGGER.debug("Rule '%s' is in group '%s', preserving group membership", rule_name, rule_group)
                # Update the rule while preserving group membership
                xml_request = self._create_update_xml_request_with_group(rule_name, enabled, full_rule_xml, rule_group, current_groups)
            else:
                # Update the rule normally (preserving position)
                xml_request = self._create_update_xml_request(rule_name, enabled, full_rule_xml)
            
            await self._make_request(xml_request)
            
            _LOGGER.info("Successfully updated rule '%s' to %s", rule_name, "enabled" if enabled else "disabled")
            return True
            
        except SophosFirewallAPIError as err:
            _LOGGER.error("Failed to set rule status for %s: %s", rule_name, err)
            return False

    def _create_update_xml_request(self, rule_name: str, enabled: bool, full_rule_data: ET.Element) -> str:
        """Create XML request to update a firewall rule preserving all settings."""
        _LOGGER.debug("Creating update XML request for rule: %s, enabled: %s", rule_name, enabled)
        
        request = ET.Element("Request")
        
        # Login section
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        # Set section with operation="update"
        set_elem = ET.SubElement(request, "Set")
        set_elem.set("operation", "update")
        
        # Create a copy of the full rule data
        import copy
        rule_elem = copy.deepcopy(full_rule_data)
        
        # Update the status in the copied rule
        status_elem = rule_elem.find("Status")
        if status_elem is not None:
            status_elem.text = "Enable" if enabled else "Disable"
        
        # Ensure the transactionid attribute is preserved or set to empty
        if not rule_elem.get("transactionid"):
            rule_elem.set("transactionid", "")
        
        # Add the updated rule to the Set element
        set_elem.append(rule_elem)
        
        xml_string = ET.tostring(request, encoding="unicode")
        _LOGGER.debug("Generated update XML request: %s", xml_string)
        return xml_string

    def _create_update_xml_request_with_group(self, rule_name: str, enabled: bool, full_rule_data: ET.Element, 
                                            group_name: str, all_groups: list) -> str:
        """Create XML request to update a firewall rule while preserving group membership."""
        _LOGGER.debug("Creating update XML request for rule: %s in group: %s, enabled: %s", 
                      rule_name, group_name, enabled)
        
        # Find the group data
        target_group = None
        for group in all_groups:
            if group.get("name") == group_name:
                target_group = group
                break
        
        if not target_group:
            _LOGGER.warning("Group '%s' not found, updating rule without group", group_name)
            return self._create_update_xml_request(rule_name, enabled, full_rule_data)
        
        request = ET.Element("Request")
        
        # Login section
        login = ET.SubElement(request, "Login")
        ET.SubElement(login, "Username").text = self.username
        ET.SubElement(login, "Password").text = self.password
        
        # Set section with operation="update"
        set_elem = ET.SubElement(request, "Set")
        set_elem.set("operation", "update")
        
        # First update the rule itself
        import copy
        rule_elem = copy.deepcopy(full_rule_data)
        
        # Update the status in the copied rule
        status_elem = rule_elem.find("Status")
        if status_elem is not None:
            status_elem.text = "Enable" if enabled else "Disable"
        
        # Ensure the transactionid attribute is preserved or set to empty
        if not rule_elem.get("transactionid"):
            rule_elem.set("transactionid", "")
        
        # Add the updated rule to the Set element
        set_elem.append(rule_elem)
        
        # Also update the group to maintain membership
        group_elem = ET.SubElement(set_elem, "FirewallRuleGroup")
        group_elem.set("transactionid", target_group.get("transactionid", ""))
        
        ET.SubElement(group_elem, "Name").text = group_name
        
        description_elem = ET.SubElement(group_elem, "Description")
        description_elem.text = target_group.get("description", "")
        
        # Add all rules in the group (including the updated one)
        policy_list = ET.SubElement(group_elem, "SecurityPolicyList")
        for rule_in_group in target_group.get("rules", []):
            policy_elem = ET.SubElement(policy_list, "SecurityPolicy")
            policy_elem.text = rule_in_group
        
        policy_type_elem = ET.SubElement(group_elem, "Policytype")
        policy_type_elem.text = target_group.get("policy_type", "User/network rule")
        
        xml_string = ET.tostring(request, encoding="unicode")
        _LOGGER.debug("Generated update XML request with group: %s", xml_string)
        return xml_string
        