# custom_components/sophos_firewall/binary_sensor.py
"""Support for Sophos Firewall binary sensors."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Sophos Firewall binary sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    
    entities = []
    
    # Check what data is actually available
    system_health = coordinator.data.get("system_health", {})
    interface_details = coordinator.data.get("interface_details", {})
    zones = coordinator.data.get("zones", {})
    
    _LOGGER.info("Available binary sensor data - Health: %d items, Interface details: %d items, Zones: %d items",
                len(system_health), len(interface_details), len(zones))
    
    # Create system service status binary sensors
    if system_health:
        _LOGGER.info("Creating system service binary sensors")
        
        services = ['antispam', 'antivirus', 'authentication', 'dhcpserver', 
                   'dnsserver', 'ips', 'webproxy', 'waf', 'dhcpv6server']
        
        for service in services:
            running_key = f"service_{service}_running"
            if running_key in system_health:
                entities.append(SophosServiceStatusSensor(coordinator, config_entry, running_key,
                                f"{service.upper()} Service", BinarySensorDeviceClass.RUNNING, "mdi:cog"))
        
        # ATP status
        if "atp_enabled" in system_health:
            entities.append(SophosSecurityFeatureSensor(coordinator, config_entry, "atp_enabled",
                            "Advanced Threat Protection", BinarySensorDeviceClass.SAFETY, "mdi:shield"))
        
        # Auto update status
        if "auto_update_enabled" in system_health:
            entities.append(SophosSecurityFeatureSensor(coordinator, config_entry, "auto_update_enabled",
                            "Pattern Auto Update", BinarySensorDeviceClass.UPDATE, "mdi:update"))
        
        # Block login enabled
        if "block_login_enabled" in system_health:
            entities.append(SophosSecurityFeatureSensor(coordinator, config_entry, "block_login_enabled",
                            "Login Security Block", BinarySensorDeviceClass.SAFETY, "mdi:account-lock"))
    
    # Create interface status binary sensors
    if interface_details:
        _LOGGER.info("Creating interface status binary sensors")
        for key, value in interface_details.items():
            if key.endswith("_status"):
                interface_name = key.replace("_status", "")
                entities.append(SophosInterfaceStatusSensor(coordinator, config_entry, key,
                                f"{interface_name} Interface", BinarySensorDeviceClass.CONNECTIVITY, "mdi:ethernet"))
    
    # Create zone security binary sensors
    if zones:
        _LOGGER.info("Creating zone security binary sensors")
        for key, value in zones.items():
            if key.endswith("_https") and isinstance(value, bool):
                zone_name = key.replace("_https", "").replace("zone_", "")
                entities.append(SophosZoneSecuritySensor(coordinator, config_entry, key,
                                f"{zone_name} HTTPS Access", BinarySensorDeviceClass.SAFETY, "mdi:lock"))
            elif key.endswith("_ssh") and isinstance(value, bool):
                zone_name = key.replace("_ssh", "").replace("zone_", "")
                entities.append(SophosZoneSecuritySensor(coordinator, config_entry, key,
                                f"{zone_name} SSH Access", BinarySensorDeviceClass.SAFETY, "mdi:console"))
    
    if entities:
        _LOGGER.info("Created %d binary sensors", len(entities))
        async_add_entities(entities, update_before_add=True)
    else:
        _LOGGER.warning("No binary sensor data available - no binary sensors created")

class SophosBaseBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Base class for Sophos Firewall binary sensors."""

    def __init__(
        self,
        coordinator,
        config_entry: ConfigEntry,
        sensor_type: str,
        name: str,
        device_class: BinarySensorDeviceClass | None,
        icon: str,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._sensor_type = sensor_type
        self._attr_name = name
        self._attr_unique_id = f"sophos_fw_alert_{config_entry.entry_id}_{sensor_type}"
        self._attr_device_class = device_class
        self._attr_icon = icon

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information about this firewall."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._config_entry.data["host"])},
            name=f"Sophos Firewall ({self._config_entry.data['host']})",
            manufacturer="Sophos",
            model="Firewall",
            sw_version=getattr(self.coordinator.api, 'api_version', 'Unknown'),
            configuration_url=f"https://{self._config_entry.data['host']}:{self._config_entry.data.get('port', 4444)}",
        )

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success

class SophosServiceStatusSensor(SophosBaseBinarySensor):
    """Binary sensor for system service status."""

    @property
    def is_on(self) -> bool:
        """Return true if the service is running."""
        system_health = self.coordinator.data.get("system_health", {})
        return system_health.get(self._sensor_type, False)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        system_health = self.coordinator.data.get("system_health", {})
        service_name = self._sensor_type.replace("service_", "").replace("_running", "")
        
        return {
            "service_action": system_health.get(f"service_{service_name}_action", "Unknown"),
            "service_status": system_health.get(f"service_{service_name}_status", "Unknown"),
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
        }

class SophosSecurityFeatureSensor(SophosBaseBinarySensor):
    """Binary sensor for security features."""

    @property
    def is_on(self) -> bool:
        """Return true if the security feature is enabled."""
        system_health = self.coordinator.data.get("system_health", {})
        return system_health.get(self._sensor_type, False)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        system_health = self.coordinator.data.get("system_health", {})
        
        attributes = {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
        }
        
        # Add specific attributes based on sensor type
        if "atp" in self._sensor_type:
            attributes["inspect_content"] = system_health.get("atp_inspect_content", "Unknown")
        elif "auto_update" in self._sensor_type:
            attributes["update_interval"] = system_health.get("update_interval", "Unknown")
        elif "logout_timeout" in self._sensor_type:
            attributes["timeout_minutes"] = system_health.get("logout_timeout", "Unknown")
        
        return attributes

class SophosInterfaceStatusSensor(SophosBaseBinarySensor):
    """Binary sensor for interface status."""

    @property
    def is_on(self) -> bool:
        """Return true if the interface is up/connected."""
        interface_details = self.coordinator.data.get("interface_details", {})
        status = interface_details.get(self._sensor_type, "").upper()
        return status in ["ON", "UP", "CONNECTED"]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        interface_details = self.coordinator.data.get("interface_details", {})
        interface_name = self._sensor_type.replace("_status", "")
        
        return {
            "interface_status": interface_details.get(self._sensor_type, "Unknown"),
            "connection_details": interface_details.get(f"{interface_name}_connection", "Unknown"),
            "ip_address": interface_details.get(f"{interface_name}_ip", "Unknown"),
            "network_zone": interface_details.get(f"{interface_name}_zone", "Unknown"),
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
        }

class SophosZoneSecuritySensor(SophosBaseBinarySensor):
    """Binary sensor for zone security settings."""

    @property
    def is_on(self) -> bool:
        """Return true if the security feature is enabled."""
        zones = self.coordinator.data.get("zones", {})
        return zones.get(self._sensor_type, False)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        zones = self.coordinator.data.get("zones", {})
        zone_name = self._sensor_type.replace("_https", "").replace("_ssh", "").replace("zone_", "")
        
        return {
            "zone_type": zones.get(f"zone_{zone_name}_type", "Unknown"),
            "https_enabled": zones.get(f"zone_{zone_name}_https", False),
            "ssh_enabled": zones.get(f"zone_{zone_name}_ssh", False),
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
        }