# custom_components/sophos_firewall/config_flow.py
"""Config flow for Sophos Firewall integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_VERIFY_SSL, DEFAULT_PORT, DEFAULT_VERIFY_SSL, DOMAIN
from .sophos_api import SophosFirewallAPI, SophosFirewallAPIError

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
    }
)

async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    _LOGGER.debug("Starting validation for Sophos Firewall connection")
    _LOGGER.debug("Host: %s, Port: %s, Username: %s, Verify SSL: %s", 
                  data[CONF_HOST], data[CONF_PORT], data[CONF_USERNAME], data[CONF_VERIFY_SSL])
    
    api = SophosFirewallAPI(
        host=data[CONF_HOST],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        port=data[CONF_PORT],
        verify_ssl=data[CONF_VERIFY_SSL],
    )

    try:
        await api.test_connection()
        _LOGGER.info("Successfully connected to Sophos Firewall at %s:%s", 
                     data[CONF_HOST], data[CONF_PORT])
    except Exception as e:
        _LOGGER.error("Failed to connect to Sophos Firewall: %s", str(e))
        raise
    finally:
        await api.close()
    
    # Return info that you want to store in the config entry.
    return {"title": f"Sophos Firewall ({data[CONF_HOST]})"}

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Sophos Firewall."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except SophosFirewallAPIError as e:
                _LOGGER.error("Sophos Firewall API error during config: %s", str(e))
                errors["base"] = "cannot_connect"
            except Exception as e:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during config: %s", str(e))
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )
