# custom_components/sophos_firewall/switch.py
"""Support for Sophos Firewall rule switches."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
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
    """Set up Sophos Firewall switches based on a config entry."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    
    entities = []
    rules_data = coordinator.data.get("rules", [])
    for rule in rules_data:
        entities.append(SophosFirewallRuleSwitch(coordinator, rule, config_entry))
    
    async_add_entities(entities, update_before_add=True)

class SophosFirewallRuleSwitch(CoordinatorEntity, SwitchEntity):
    """Representation of a Sophos Firewall rule switch."""

    def __init__(self, coordinator, rule_data: dict[str, Any], config_entry: ConfigEntry) -> None:
        """Initialize the switch."""
        super().__init__(coordinator)
        self._rule_data = rule_data
        self._config_entry = config_entry
        self._attr_name = f"Firewall Rule: {rule_data['name']}"
        self._attr_unique_id = f"sophos_fw_rule_{config_entry.entry_id}_{rule_data['name']}"

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
    def is_on(self) -> bool:
        """Return true if the switch is on."""
        # Find current rule data in coordinator
        rules_data = self.coordinator.data.get("rules", [])
        for rule in rules_data:
            if rule["name"] == self._rule_data["name"]:
                return rule.get("enabled", False)
        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        # Find current rule data in coordinator
        rules_data = self.coordinator.data.get("rules", [])
        for rule in rules_data:
            if rule["name"] == self._rule_data["name"]:
                return {
                    "description": rule.get("description", ""),
                    "source_zones": rule.get("source_zones", ""),
                    "destination_zones": rule.get("destination_zones", ""),
                    "action": rule.get("action", ""),
                    "policy_type": rule.get("policy_type", ""),
                    "ip_family": rule.get("ip_family", ""),
                    "position": rule.get("position", ""),
                    "after_rule": rule.get("after_rule", ""),
                    "group": rule.get("group", ""),
                    "rule_name": rule["name"],
                }
        return {}

    @property
    def icon(self) -> str:
        """Return the icon for the switch."""
        return "mdi:firewall" if self.is_on else "mdi:firewall-off"

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        success = await self.coordinator.api.set_rule_status(
            self._rule_data["name"], True
        )
        if success:
            await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
        success = await self.coordinator.api.set_rule_status(
            self._rule_data["name"], False
        )
        if success:
            await self.coordinator.async_request_refresh()

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success
