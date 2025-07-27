# custom_components/sophos_firewall/sensor.py
"""Support for Sophos Firewall sensors."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorDeviceClass,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfInformation,
    UnitOfTime,
    UnitOfTemperature,
)
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
    """Set up Sophos Firewall sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    
    entities = []
    
    # Check what data is actually available
    system_health = coordinator.data.get("system_health", {})
    traffic_stats = coordinator.data.get("traffic_stats", {})
    interface_details = coordinator.data.get("interface_details", {})
    zones = coordinator.data.get("zones", {})
    backup_info = coordinator.data.get("backup_info", {})
    dns_info = coordinator.data.get("dns_info", {})
    dhcp_info = coordinator.data.get("dhcp_info", {})
    time_info = coordinator.data.get("time_info", {})
    
    _LOGGER.info("Available sensor data - Health: %d items, Traffic: %d items, Interface: %d items, Zones: %d items",
                len(system_health), len(traffic_stats), len(interface_details), len(zones))
    
    # Create system health sensors
    if system_health:
        _LOGGER.info("Creating system health sensors")
        
        # Hostname sensor
        if "hostname" in system_health:
            entities.append(SophosSystemInfoSensor(coordinator, config_entry, "hostname", "Hostname", 
                           None, "mdi:server"))
        
        # HTTPS port sensor
        if "https_port" in system_health:
            entities.append(SophosSystemInfoSensor(coordinator, config_entry, "https_port", "HTTPS Port", 
                           None, "mdi:ethernet"))
        
        # Logout timeout sensor
        if "logout_timeout" in system_health:
            entities.append(SophosSystemInfoSensor(coordinator, config_entry, "logout_timeout", "Session Timeout", 
                           "minutes", "mdi:timer"))
    
    # Create interface usage sensors
    if traffic_stats:
        _LOGGER.info("Creating interface usage sensors")
        for key, value in traffic_stats.items():
            if key.endswith("_usage") and isinstance(value, (int, float)):
                interface_name = key.replace("_usage", "")
                entities.append(SophosInterfaceUsageSensor(coordinator, config_entry, key, 
                                f"{interface_name} Usage", "usage_level", "mdi:network"))
    
    # Create interface detail sensors  
    if interface_details:
        _LOGGER.info("Creating interface detail sensors")
        for key, value in interface_details.items():
            if key.endswith("_status"):
                interface_name = key.replace("_status", "")
                entities.append(SophosInterfaceDetailSensor(coordinator, config_entry, key,
                                f"{interface_name} Status", None, "mdi:ethernet"))
            elif key.endswith("_connection"):
                interface_name = key.replace("_connection", "")
                entities.append(SophosInterfaceDetailSensor(coordinator, config_entry, key,
                                f"{interface_name} Connection", None, "mdi:ethernet-cable"))
            elif key.endswith("_ip"):
                interface_name = key.replace("_ip", "")
                entities.append(SophosInterfaceDetailSensor(coordinator, config_entry, key,
                                f"{interface_name} IP Address", None, "mdi:ip"))
    
    # Create zone information sensors
    if zones:
        _LOGGER.info("Creating zone sensors")
        if "total_zones" in zones:
            entities.append(SophosZoneSensor(coordinator, config_entry, "total_zones",
                            "Total Security Zones", "zones", "mdi:security"))
    
    # Create backup information sensors
    if backup_info:
        _LOGGER.info("Creating backup sensors")
        if "backup_mode" in backup_info:
            entities.append(SophosBackupSensor(coordinator, config_entry, "backup_mode",
                            "Backup Mode", None, "mdi:backup-restore"))
        if "backup_frequency" in backup_info:
            entities.append(SophosBackupSensor(coordinator, config_entry, "backup_frequency",
                            "Backup Frequency", None, "mdi:calendar-clock"))
    
    # Create DNS sensors
    if dns_info:
        _LOGGER.info("Creating DNS sensors")
        if "primary_dns" in dns_info:
            entities.append(SophosDNSSensor(coordinator, config_entry, "primary_dns",
                            "Primary DNS Server", None, "mdi:dns"))
        if "secondary_dns" in dns_info:
            entities.append(SophosDNSSensor(coordinator, config_entry, "secondary_dns",
                            "Secondary DNS Server", None, "mdi:dns"))
    
    # Create DHCP sensors
    if dhcp_info:
        _LOGGER.info("Creating DHCP sensors")
        if "dhcp_options_count" in dhcp_info:
            entities.append(SophosDHCPSensor(coordinator, config_entry, "dhcp_options_count",
                            "DHCP Options Count", "options", "mdi:router-network"))
    
    # Create time sensors
    if time_info:
        _LOGGER.info("Creating time sensors")
        if "timezone" in time_info:
            entities.append(SophosTimeSensor(coordinator, config_entry, "timezone",
                            "System Timezone", None, "mdi:map-clock"))
    
    if entities:
        _LOGGER.info("Created %d sensors", len(entities))
        async_add_entities(entities, update_before_add=True)
    else:
        _LOGGER.warning("No sensor data available - no sensors created")

class SophosBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for Sophos Firewall sensors."""

    def __init__(
        self,
        coordinator,
        config_entry: ConfigEntry,
        sensor_type: str,
        name: str,
        unit: str | None,
        icon: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._config_entry = config_entry
        self._sensor_type = sensor_type
        self._attr_name = name
        self._attr_unique_id = f"sophos_fw_{config_entry.entry_id}_{sensor_type}"
        self._attr_native_unit_of_measurement = unit
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

class SophosSystemInfoSensor(SophosBaseSensor):
    """Sophos Firewall system information sensor."""

    @property
    def native_value(self) -> str | int | None:
        """Return the value reported by the sensor."""
        system_health = self.coordinator.data.get("system_health", {})
        return system_health.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "system_health"
        }

class SophosInterfaceUsageSensor(SophosBaseSensor):
    """Sophos Firewall interface usage sensor."""

    def __init__(
        self,
        coordinator,
        config_entry: ConfigEntry,
        sensor_type: str,
        name: str,
        unit: str | None,
        icon: str,
    ) -> None:
        """Initialize the interface usage sensor."""
        super().__init__(coordinator, config_entry, sensor_type, name, unit, icon)
        self._attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def native_value(self) -> int | None:
        """Return the value reported by the sensor."""
        traffic_stats = self.coordinator.data.get("traffic_stats", {})
        return traffic_stats.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "interface_statistics"
        }

class SophosInterfaceDetailSensor(SophosBaseSensor):
    """Sophos Firewall interface detail sensor."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the sensor."""
        interface_details = self.coordinator.data.get("interface_details", {})
        return interface_details.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "interface_details"
        }

class SophosZoneSensor(SophosBaseSensor):
    """Sophos Firewall zone information sensor."""

    def __init__(
        self,
        coordinator,
        config_entry: ConfigEntry,
        sensor_type: str,
        name: str,
        unit: str | None,
        icon: str,
    ) -> None:
        """Initialize the zone sensor."""
        super().__init__(coordinator, config_entry, sensor_type, name, unit, icon)
        self._attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def native_value(self) -> int | str | None:
        """Return the value reported by the sensor."""
        zones = self.coordinator.data.get("zones", {})
        return zones.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        zones = self.coordinator.data.get("zones", {})
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "zones",
            "all_zones": {k: v for k, v in zones.items() if not k.startswith("zone_")}
        }

class SophosBackupSensor(SophosBaseSensor):
    """Sophos Firewall backup information sensor."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the sensor."""
        backup_info = self.coordinator.data.get("backup_info", {})
        return backup_info.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        backup_info = self.coordinator.data.get("backup_info", {})
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "backup_info",
            "all_backup_data": backup_info
        }

class SophosDNSSensor(SophosBaseSensor):
    """Sophos Firewall DNS information sensor."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the sensor."""
        dns_info = self.coordinator.data.get("dns_info", {})
        return dns_info.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        dns_info = self.coordinator.data.get("dns_info", {})
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "dns_info",
            "all_dns_data": dns_info
        }

class SophosDHCPSensor(SophosBaseSensor):
    """Sophos Firewall DHCP information sensor."""

    @property
    def native_value(self) -> int | None:
        """Return the value reported by the sensor."""
        dhcp_info = self.coordinator.data.get("dhcp_info", {})
        return dhcp_info.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        dhcp_info = self.coordinator.data.get("dhcp_info", {})
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "dhcp_info"
        }

class SophosTimeSensor(SophosBaseSensor):
    """Sophos Firewall time information sensor."""

    @property
    def native_value(self) -> str | None:
        """Return the value reported by the sensor."""
        time_info = self.coordinator.data.get("time_info", {})
        return time_info.get(self._sensor_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        time_info = self.coordinator.data.get("time_info", {})
        return {
            "last_updated": getattr(self.coordinator, 'last_update_success_time', None),
            "data_source": "time_info",
            "all_time_data": time_info
        }