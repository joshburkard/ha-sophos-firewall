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
        self._attr_name = f"FWR: {rule_data['name']}"
        self._attr_unique_id = f"sophos_fw_rule_{config_entry.entry_id}_{rule_data['name']}"
        self._last_known_state = None
        self._updating = False

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
        # If we're currently updating, return the last known state to prevent flickering
        if self._updating and self._last_known_state is not None:
            return self._last_known_state
        
        # Find current rule data in coordinator
        rules_data = self.coordinator.data.get("rules", [])
        for rule in rules_data:
            if rule["name"] == self._rule_data["name"]:
                current_state = rule.get("enabled", False)
                self._last_known_state = current_state
                return current_state
        
        # Fallback to last known state if rule not found
        return self._last_known_state if self._last_known_state is not None else False

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
                    "updating": self._updating,
                }
        return {"updating": self._updating}

    @property
    def icon(self) -> str:
        """Return the icon for the switch."""
        if self._updating:
            return "mdi:loading"
        return "mdi:firewall" if self.is_on else "mdi:firewall-off"

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the switch on."""
        await self._async_set_rule_status(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the switch off."""
        await self._async_set_rule_status(False)

    async def _async_set_rule_status(self, enabled: bool) -> None:
        """Set the rule status with proper state management."""
        import asyncio
        
        _LOGGER.info("Switch: Setting rule '%s' to %s", self._rule_data["name"], "on" if enabled else "off")
        
        # Set updating flag and update UI
        self._updating = True
        self.async_write_ha_state()
        
        try:
            # Call the API
            success = await self.coordinator.api.set_rule_status(
                self._rule_data["name"], enabled
            )
            
            if success:
                _LOGGER.info("Switch: API call successful for rule '%s'", self._rule_data["name"])
                
                # Wait a bit for the change to propagate
                await asyncio.sleep(2)
                
                # Force a coordinator refresh
                await self.coordinator.async_request_refresh()
                
                # Wait for the refresh to complete
                await asyncio.sleep(1)
                
                # Verify the state change
                rules_data = self.coordinator.data.get("rules", [])
                for rule in rules_data:
                    if rule["name"] == self._rule_data["name"]:
                        actual_state = rule.get("enabled", False)
                        if actual_state == enabled:
                            _LOGGER.info("Switch: State change verified for rule '%s'", self._rule_data["name"])
                        else:
                            _LOGGER.warning("Switch: State change not yet reflected for rule '%s' - expected: %s, actual: %s", 
                                          self._rule_data["name"], enabled, actual_state)
                            # Try one more refresh after a longer delay
                            await asyncio.sleep(3)
                            await self.coordinator.async_request_refresh()
                        break
            else:
                _LOGGER.error("Switch: API call failed for rule '%s'", self._rule_data["name"])
                
        except Exception as e:
            _LOGGER.error("Switch: Error setting rule status for '%s': %s", self._rule_data["name"], e)
        
        finally:
            # Clear updating flag and update UI
            self._updating = False
            self.async_write_ha_state()
