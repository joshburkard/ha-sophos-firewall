# HA-Sophos-Firewall

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

Adds an integration for the Sophos Firewall API to Home Assistant. This integration requires [HACS](https://hacs.xyz).

# Features

this features are already integrated:

## Firewall Rules

- get existing firewall rules
- enable / disable firewall rules

# Setup

Recommended to be installed via [HACS](https://github.com/hacs/integration)

1. open your [Home Assistant](https://www.home-assistant.io/) instance
2. Go to [HACS](https://hacs.xyz)
3. click on the 3 dots top right and select `Custom Repositories`
4. type in repository `https://github.com/joshburkard/ha-sophos-firewall`
5. select the Type `Integration` and click `ADD`
6. Search for `Sophos Firewall`
7. click on the 3 dots on the `Sophos Firewall` row and select `Download`
8. Restart [Home Assistant](https://www.home-assistant.io/)
9. Go to `Settings` --> `Devices & Services`
10. Click to `Add Integration`
11. Search for `Sophos Firewall`
12. Enter the IP-Address, username and password for the API user and click to `Submit`.
13. use it

## Change Log

here you will find the [Change Log](changelog.md)