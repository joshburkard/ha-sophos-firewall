# custom_components/sophos_firewall/__init__.py
"""The Sophos Firewall integration."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN
from .sophos_api import SophosFirewallAPI

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SWITCH]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Sophos Firewall from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    api = SophosFirewallAPI(
        host=entry.data["host"],
        username=entry.data["username"],
        password=entry.data["password"],
        port=entry.data.get("port", 4444),
        verify_ssl=entry.data.get("verify_ssl", True),
    )

    coordinator = SophosFirewallDataUpdateCoordinator(hass, api, entry)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Create device registry entry
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.data["host"])},
        name=f"Sophos Firewall ({entry.data['host']})",
        manufacturer="Sophos",
        model="Firewall",
        sw_version=getattr(coordinator.api, 'api_version', 'Unknown'),
        configuration_url=f"https://{entry.data['host']}:{entry.data.get('port', 4444)}",
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok

class SophosFirewallDataUpdateCoordinator(DataUpdateCoordinator):
    """Class to manage fetching data from the Sophos Firewall API."""

    def __init__(self, hass: HomeAssistant, api: SophosFirewallAPI, entry: ConfigEntry) -> None:
        """Initialize."""
        self.api = api
        self.entry = entry
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=30),
        )

    async def _async_update_data(self):
        """Update data via library."""
        try:
            return await self.api.get_firewall_rules()
        except Exception as exception:
            raise UpdateFailed(exception) from exception
