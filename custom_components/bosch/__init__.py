"""Platform to control a Bosch IP thermostats units."""
from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable
from datetime import timedelta
from typing import Any

import homeassistant.helpers.config_validation as cv
import voluptuous as vol
from bosch_thermostat_client.const import (
    DHW,
    HC,
    HTTP,
    NUMBER,
    RECORDING,
    SC,
    SELECT,
    SENSOR,
    ZN,
)
from bosch_thermostat_client.const.easycontrol import DV
from bosch_thermostat_client.exceptions import (
    DeviceException,
    EncryptionException,
    FirmwareException,
    UnknownDevice,
)
from bosch_thermostat_client.version import __version__ as LIBVERSION
from homeassistant.components.persistent_notification import (
    async_create as async_create_persistent_notification,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    ATTR_ENTITY_ID,
    CONF_ADDRESS,
    EVENT_HOMEASSISTANT_STOP,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.dispatcher import (
    async_dispatcher_connect,
    async_dispatcher_send,
)
from homeassistant.helpers.event import (
    async_call_later,
    async_track_point_in_utc_time,
    async_track_time_interval,
)
from homeassistant.helpers.json import save_json
from homeassistant.helpers.network import get_url
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import dt as dt_util
from homeassistant.util.json import load_json

from custom_components.bosch.switch import SWITCH

from .const import (
    ACCESS_KEY,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    BINARY_SENSOR,
    BOSCH_GATEWAY_ENTRY,
    CLIMATE,
    CONF_DEVICE_TYPE,
    CONF_PROTOCOL,
    DOMAIN,
    FIRMWARE_SCAN_INTERVAL,
    FW_INTERVAL,
    GATEWAY,
    INTERVAL,
    NOTIFICATION_ID,
    POINTTAPI,
    RECORDING_INTERVAL,
    SCAN_INTERVAL,
    SIGNAL_BINARY_SENSOR_UPDATE_BOSCH,
    SIGNAL_BOSCH,
    SIGNAL_CLIMATE_UPDATE_BOSCH,
    SIGNAL_DHW_UPDATE_BOSCH,
    SIGNAL_NUMBER,
    SIGNAL_SELECT,
    SIGNAL_SENSOR_UPDATE_BOSCH,
    SIGNAL_SOLAR_UPDATE_BOSCH,
    SIGNAL_SWITCH,
    SOLAR,
    UUID,
    WATER_HEATER,
)
from .services import (
    async_register_debug_service,
    async_register_services,
    async_remove_services,
)

SIGNALS = {
    CLIMATE: SIGNAL_CLIMATE_UPDATE_BOSCH,
    WATER_HEATER: SIGNAL_DHW_UPDATE_BOSCH,
    SENSOR: SIGNAL_SENSOR_UPDATE_BOSCH,
    BINARY_SENSOR: SIGNAL_BINARY_SENSOR_UPDATE_BOSCH,
    SOLAR: SIGNAL_SOLAR_UPDATE_BOSCH,
    SWITCH: SIGNAL_SWITCH,
    SELECT: SIGNAL_SELECT,
    NUMBER: SIGNAL_NUMBER,
}

SUPPORTED_PLATFORMS = {
    HC: [CLIMATE],
    DHW: [WATER_HEATER],
    SWITCH: [SWITCH],
    SELECT: [SELECT],
    NUMBER: [NUMBER],
    SC: [SENSOR],
    SENSOR: [SENSOR, BINARY_SENSOR],
    ZN: [CLIMATE],
    DV: [SENSOR],
}


CUSTOM_DB = "custom_bosch_db.json"
SERVICE_DEBUG_SCHEMA = vol.Schema({vol.Required(ATTR_ENTITY_ID): cv.entity_ids})
SERVICE_INTEGRATION_SCHEMA = vol.Schema({vol.Required(UUID): int})

TASK = "task"

DATA_CONFIGS = "bosch_configs"

_LOGGER = logging.getLogger(__name__)

HOUR = timedelta(hours=1)


async def async_setup(hass: HomeAssistant, config: ConfigType):
    """Initialize the Bosch platform."""
    hass.data[DOMAIN] = {}
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Create entry for Bosch thermostat device."""
    _LOGGER.info(f"Setting up Bosch component version {LIBVERSION}.")
    uuid = entry.data[UUID]
    
    # Log the entry data for debugging
    _LOGGER.info(f"[Setup Entry] Keys in entry.data: {list(entry.data.keys())}")
    _LOGGER.info(f"[Setup Entry] REFRESH_TOKEN constant: '{REFRESH_TOKEN}'")
    refresh_token_value = entry.data.get(REFRESH_TOKEN)
    _LOGGER.info(f"[Setup Entry] refresh_token from entry.data.get(REFRESH_TOKEN): {refresh_token_value is not None}")
    if refresh_token_value:
        _LOGGER.debug(f"[Setup Entry] refresh_token value (first 30 chars): {refresh_token_value[:30]}...")
    
    entry.async_on_unload(entry.add_update_listener(async_update_options))
    gateway_entry = BoschGatewayEntry(
        hass=hass,
        uuid=uuid,
        host=entry.data[CONF_ADDRESS],
        protocol=entry.data[CONF_PROTOCOL],
        device_type=entry.data[CONF_DEVICE_TYPE],
        access_key=entry.data.get(ACCESS_KEY),
        access_token=entry.data[ACCESS_TOKEN],
        refresh_token=entry.data.get(REFRESH_TOKEN),
        entry=entry,
    )
    hass.data[DOMAIN][uuid] = {BOSCH_GATEWAY_ENTRY: gateway_entry}
    _init_status: bool = await gateway_entry.async_init()
    if not _init_status:
        return _init_status
    async_register_services(hass, entry)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry):
    """Unload a config entry."""
    _LOGGER.debug("Removing entry.")
    uuid = entry.data[UUID]
    data = hass.data[DOMAIN][uuid]

    def remove_entry(key):
        value = data.pop(key, None)
        if value:
            value()

    remove_entry(INTERVAL)
    remove_entry(FW_INTERVAL)
    remove_entry(RECORDING_INTERVAL)
    bosch = hass.data[DOMAIN].pop(uuid)
    unload_ok = await bosch[BOSCH_GATEWAY_ENTRY].async_reset()
    async_remove_services(hass, entry)
    return unload_ok


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry):
    """Reload entry if options change (but not if just tokens update)."""
    # We track the old data to detect what actually changed
    # Tokens should update without reloading
    if hasattr(async_update_options, '_last_data'):
        old_data = async_update_options._last_data
        new_data = entry.data
        
        # Check if only tokens changed
        token_keys = {ACCESS_TOKEN, REFRESH_TOKEN}
        config_keys = set(new_data.keys()) - token_keys
        
        old_config = {k: old_data.get(k) for k in config_keys if k in old_data}
        new_config = {k: new_data.get(k) for k in config_keys if k in new_data}
        
        # If config (non-token) data is the same, don't reload
        if old_config == new_config:
            _LOGGER.debug("[Update Listener] Only tokens changed, skipping reload")
            async_update_options._last_data = dict(new_data)
            return
    
    # Store current data for next check
    async_update_options._last_data = dict(entry.data)
    
    _LOGGER.debug("Config entry changed, reloading entry %s", entry.entry_id)
    await hass.config_entries.async_reload(entry.entry_id)


def create_notification_firmware(hass: HomeAssistant, msg):
    """Create notification about firmware to the user."""
    async_create_persistent_notification(
        hass,
        title="Bosch info",
        message=(
            "There are problems with config of your thermostat.\n"
            f"{msg}.\n"
            "You can create issue on Github, but first\n"
            "Go to [Developer Tools/Service](/developer-tools/service) and create bosch.debug_scan.\n"
            "[BoschGithub](https://github.com/bosch-thermostat/home-assistant-bosch-custom-component)"
        ),
        notification_id=NOTIFICATION_ID,
    )


class BoschGatewayEntry:
    """Bosch gateway entry config class."""

    def __init__(
        self, hass, uuid, host, protocol, device_type, access_key, access_token, entry, refresh_token=None
    ) -> None:
        """Init Bosch gateway entry config class."""
        self.hass = hass
        self.uuid = uuid
        self._host = host
        self._access_key = access_key
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._device_type = device_type
        self._protocol = protocol
        _LOGGER.info(f"[BoschGatewayEntry.__init__] protocol param: '{protocol}', device_type: '{device_type}', refresh_token: {refresh_token is not None}")
        self.config_entry = entry
        self._debug_service_registered = False
        self.gateway = None
        self.prefs = None
        self._initial_update = False
        self._signal_registered = False
        self._initialized = False
        self.supported_platforms = []
        self._update_lock = None

    @property
    def device_id(self) -> str:
        return self.config_entry.entry_id

    async def async_init(self) -> bool:
        """Init async items in entry."""
        import bosch_thermostat_client as bosch

        _LOGGER.debug("Initializing Bosch integration.")
        _LOGGER.debug(f"Device type: {self._device_type}, Protocol: {self._protocol}, POINTTAPI: {POINTTAPI}, match: {self._device_type == POINTTAPI}")
        _LOGGER.info(f"[Init] Protocol value: '{self._protocol}' (type: {type(self._protocol).__name__}), checking OAUTH2: {self._protocol == 'OAUTH2'}")
        self._update_lock = asyncio.Lock()
        
        try:
            # If using OAuth2 protocol or POINTTAPI device type, use Oauth2Gateway
            if self._protocol == "OAUTH2" or self._device_type == POINTTAPI:
                _LOGGER.info(f"[Init] Condition matched! Protocol={self._protocol}, POINTTAPI={self._device_type == POINTTAPI}")
                try:
                    from bosch_thermostat_client.gateway.oauth2 import Oauth2Gateway
                    BoschGateway = Oauth2Gateway
                    _LOGGER.info(f"✓ [Init] Successfully imported and using Oauth2Gateway")
                except ImportError as import_err:
                    _LOGGER.error(f"Failed to import Oauth2Gateway: {import_err}")
                    raise
            else:
                _LOGGER.info(f"[Init] Condition NOT matched. Protocol={self._protocol}, POINTTAPI={self._device_type == POINTTAPI}")
                BoschGateway = bosch.gateway_chooser(device_type=self._device_type)
                _LOGGER.info(f"[Init] Using gateway_chooser for device_type={self._device_type}")
        except (KeyError, ValueError) as err:
            _LOGGER.warning(f"Device type {self._device_type} not found in gateway_chooser, attempting POINTTAPI as fallback: {err}")
            # Fallback for unknown device types (like K30RF with brand='unknown')
            try:
                BoschGateway = bosch.gateway_chooser(POINTTAPI)
            except Exception as fallback_err:
                _LOGGER.error(f"Could not select gateway for device type {self._device_type}: {fallback_err}")
                return False
        
        # Build gateway kwargs
        gateway_kwargs = {
            "host": self._host,
            "access_token": self._access_token,
        }
        
        # Add parameters based on protocol/device type
        if self._protocol == "OAUTH2" or self._device_type == POINTTAPI:
            # Oauth2Gateway for OAuth2 protocol or POINTTAPI device
            gateway_kwargs["session"] = async_get_clientsession(self.hass, verify_ssl=False)
            gateway_kwargs["device_type"] = self._device_type
        else:
            # Other device types (HTTP/XMPP)
            gateway_kwargs["session_type"] = self._protocol
            if self._access_key:
                gateway_kwargs["access_key"] = self._access_key
            if self._protocol == HTTP:
                gateway_kwargs["session"] = async_get_clientsession(self.hass, verify_ssl=False)
        
        if self._refresh_token is not None:
            gateway_kwargs["refresh_token"] = self._refresh_token
        
        _LOGGER.debug(f"Gateway init kwargs: {list(gateway_kwargs.keys())}")
        
        try:
            self.gateway = BoschGateway(**gateway_kwargs)
            # Simple token sync: patch the refresh method to update config entry
            if hasattr(self.gateway, '_connector') and hasattr(self.gateway._connector, '_refresh_access_token'):
                orig_refresh = self.gateway._connector._refresh_access_token
                
                async def token_sync_refresh(*args, **kwargs):
                    _LOGGER.debug("[Token Sync] Refreshing access token...")
                    result = await orig_refresh(*args, **kwargs)
                    
                    # Update config entry with fresh tokens after successful refresh
                    # Save tokens immediately after successful refresh
                    if result:
                        new_refresh_token = getattr(self.gateway._connector, '_refresh_token', None)
                        new_access_token = getattr(self.gateway._connector, '_access_token', None)
                        
                        if new_refresh_token and new_refresh_token != self._refresh_token:
                            _LOGGER.info("[Token Sync] Updating config entry with fresh tokens")
                            new_data = dict(self.config_entry.data)
                            new_data[REFRESH_TOKEN] = new_refresh_token
                            if new_access_token:
                                new_data[ACCESS_TOKEN] = new_access_token
                            
                            # Update local copies
                            self._refresh_token = new_refresh_token
                            self._access_token = new_access_token
                            
                            # Update config entry directly - returns boolean, don't await
                            try:
                                result = self.hass.config_entries.async_update_entry(self.config_entry, data=new_data)
                                _LOGGER.debug(f"[Token Sync] Config entry updated: {result}")
                            except Exception as e:
                                _LOGGER.error(f"[Token Sync] Failed to update config entry: {e}")
                    
                    return result
                
                # Replace the refresh method
                self.gateway._connector._refresh_access_token = token_sync_refresh
        except Exception as init_err:
            error_msg = str(init_err)
            if "not find supported device" in error_msg or "unsupported" in error_msg.lower():
                _LOGGER.error(f"Library device validation failed: {init_err}. Device may still work but library detected unsupported device.")
                # Attempt to create device anyway - some K30RF devices have non-standard module tokens
                try:
                    self.gateway = BoschGateway(**gateway_kwargs)
                except Exception as retry_err:
                    _LOGGER.error(f"Failed to create Oauth2Gateway even after retry: {retry_err}")
                    # Try to continue anyway - device might be partially functional
                    _LOGGER.warning("Attempting to continue with minimal gateway setup")
                    self.gateway = None
            else:
                _LOGGER.error(f"Failed to initialize gateway: {init_err}")
                return False

        async def close_connection(event) -> None:
            """Close connection with server."""
            _LOGGER.debug("Closing connection to Bosch")
            await self.gateway.close()

        if await self.async_init_bosch():
            self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, close_connection)
            async_dispatcher_connect(
                self.hass, SIGNAL_BOSCH, self.async_get_signals
            )
            await self.hass.config_entries.async_forward_entry_setups(
                self.config_entry,
                [component for component in self.supported_platforms if component != SOLAR]
            )
            device_registry = dr.async_get(self.hass)
            device_registry.async_get_or_create(
                config_entry_id=self.config_entry.entry_id,
                identifiers={(DOMAIN, self.uuid)},
                manufacturer=self.gateway.device_model,
                model=self.gateway.device_type,
                name=self.gateway.device_name,
                sw_version=self.gateway.firmware,
            )
            if GATEWAY in self.hass.data[DOMAIN][self.uuid]:
                _LOGGER.debug("Registering debug services.")
                async_register_debug_service(hass=self.hass, entry=self)
            _LOGGER.debug(
                "Bosch component registered with platforms %s.",
                self.supported_platforms,
            )
            self._initialized = True
            return True
        return False

    @callback
    def async_get_signals(self) -> None:
        """Prepare update after all entities are loaded."""
        if not self._signal_registered and all(
            k in self.hass.data[DOMAIN][self.uuid] for k in self.supported_platforms
        ):
            _LOGGER.debug("Registering thermostat update interval.")
            self._signal_registered = True
            self.hass.data[DOMAIN][self.uuid][INTERVAL] = async_track_time_interval(
                self.hass, self.thermostat_refresh, SCAN_INTERVAL
            )
            self.hass.data[DOMAIN][self.uuid][FW_INTERVAL] = async_track_time_interval(
                self.hass,
                self.firmware_refresh,
                FIRMWARE_SCAN_INTERVAL,  # SCAN INTERVAL FV
            )
            async_call_later(self.hass, 5, self.thermostat_refresh)
            asyncio.run_coroutine_threadsafe(self.recording_sensors_update(),
                self.hass.loop
            )

    async def async_init_bosch(self) -> bool:
        """Initialize Bosch gateway module."""
        _LOGGER.debug("Checking connection to Bosch gateway as %s.", self._host)
        try:
            await self.gateway.check_connection()
        except (FirmwareException) as err:
            create_notification_firmware(hass=self.hass, msg=err)
            _LOGGER.error(err)
            return False
        except (UnknownDevice, EncryptionException) as err:
            _LOGGER.error(err)
            _LOGGER.error("You might need to check your password.")
            raise ConfigEntryNotReady(
                "Cannot connect to Bosch gateway, host %s with UUID: %s",
                self._host,
                self.uuid,
            )
        if not self.gateway.uuid:
            raise ConfigEntryNotReady(
                "Cannot connect to Bosch gateway, host %s with UUID: %s",
                self._host,
                self.uuid,
            )
        _LOGGER.debug("Bosch BUS detected: %s", self.gateway.bus_type)
        if not self.gateway.database:
            custom_db = load_json(self.hass.config.path(CUSTOM_DB), default=None)
            if custom_db:
                _LOGGER.info("Loading custom db file.")
                await self.gateway.custom_initialize(custom_db)
        if self.gateway.database:
            supported_bosch = await self.gateway.get_capabilities()
            _LOGGER.debug(f"Bosch supported capabilities: {supported_bosch}")
            for supported in supported_bosch:
                if supported not in SUPPORTED_PLATFORMS:
                    _LOGGER.warning(
                        "Circuit type '%s' is not supported by this custom component. Skipping.",
                        supported
                    )
                    continue
                elements = SUPPORTED_PLATFORMS[supported]
                for element in elements:
                    if element not in self.supported_platforms:
                        self.supported_platforms.append(element)
        self.hass.data[DOMAIN][self.uuid][GATEWAY] = self.gateway
        _LOGGER.info("Bosch initialized.")
        return True

    async def recording_sensors_update(self, now=None) -> bool | None:
        """Update of 1-hour sensors.

        It suppose to be called only once an hour
        so sensor get's average data from Bosch.
        """
        entities = self.hass.data[DOMAIN][self.uuid].get(RECORDING, [])
        if not entities:
            return
        recording_callback = self.hass.data[DOMAIN][self.uuid].pop(
            RECORDING_INTERVAL, None
        )
        if recording_callback is not None:
            recording_callback()
            recording_callback = None
        updated = False
        signals = []
        now = dt_util.now()
        for entity in entities:
            if entity.enabled:
                try:
                    _LOGGER.debug("Updating component 1-hour Sensor by %s", id(self))
                    await entity.bosch_object.update(time=now)
                    updated = True
                    if entity.signal not in signals:
                        signals.append(entity.signal)
                except DeviceException as err:
                    _LOGGER.warning(
                        "Bosch object of entity %s is no longer available. %s",
                        entity.name,
                        err,
                    )

        def rounder(t):
            matching_seconds = [0]
            matching_minutes = [6]  # 6
            matching_hours = dt_util.parse_time_expression("*", 0, 23)
            return dt_util.find_next_time_expression_time(
                t, matching_seconds, matching_minutes, matching_hours
            )

        nexti = rounder(now + timedelta(seconds=1))
        self.hass.data[DOMAIN][self.uuid][
            RECORDING_INTERVAL
        ] = async_track_point_in_utc_time(
            self.hass, self.recording_sensors_update, nexti
        )
        _LOGGER.debug("Next update of 1-hour sensors scheduled at: %s", nexti)
        if updated:
            _LOGGER.debug("Bosch 1-hour entitites updated.")
            for signal in signals:
                async_dispatcher_send(self.hass, signal)
            return True

    async def custom_put(self, path: str, value: Any) -> None:
        """Send PUT directly to gateway without parsing."""
        await self.gateway.raw_put(path=path, value=value)

    async def custom_get(self, path) -> str:
        """Fetch value from gateway."""
        async with self._update_lock:
            return await self.gateway.raw_query(path=path)

    async def component_update(self, component_type=None, event_time=None):
        """Update data from HC, DHW, ZN, Sensors, Switch."""
        if component_type in self.supported_platforms:
            # Guard: check if component has been registered before accessing
            if component_type not in self.hass.data[DOMAIN][self.uuid]:
                _LOGGER.debug(
                    "Component %s not yet registered in hass.data, skipping update",
                    component_type,
                )
                return
                
            updated = False
            entities = self.hass.data[DOMAIN][self.uuid][component_type]
            for entity in entities:
                if entity.enabled:
                    try:
                        _LOGGER.debug(
                            "Updating component %s %s by %s",
                            component_type,
                            entity.entity_id,
                            id(self),
                        )
                        await entity.bosch_object.update()
                        updated = True
                    except DeviceException as err:
                        _LOGGER.warning(
                            "Bosch object of entity %s is no longer available. %s",
                            entity.name,
                            err,
                        )
            if updated:
                _LOGGER.debug(f"Bosch {component_type   } entitites updated.")
                async_dispatcher_send(self.hass, SIGNALS[component_type])
                return True
        return False

    async def thermostat_refresh(self, event_time=None):
        """Call Bosch to refresh information."""
        if self._update_lock.locked():
            _LOGGER.debug("Update already in progress. Not updating.")
            return
        _LOGGER.debug("Updating Bosch thermostat entitites.")
        async with self._update_lock:
            await self.component_update(SENSOR, event_time)
            await self.component_update(BINARY_SENSOR, event_time)
            await self.component_update(CLIMATE, event_time)
            await self.component_update(WATER_HEATER, event_time)
            await self.component_update(SWITCH, event_time)
            await self.component_update(NUMBER, event_time)
            _LOGGER.debug("Finish updating entities. Waiting for next scheduled check.")

    async def firmware_refresh(self, event_time=None):
        """Call Bosch to refresh firmware info."""
        if self._update_lock.locked():
            _LOGGER.debug("Update already in progress. Not updating.")
            return
        _LOGGER.debug("Updating info about Bosch firmware.")
        try:
            async with self._update_lock:
                await self.gateway.check_firmware_validity()
        except FirmwareException as err:
            create_notification_firmware(hass=self.hass, msg=err)

    async def make_rawscan(self, filename: str) -> dict:
        """Create rawscan from service."""
        rawscan = {}
        async with self._update_lock:
            _LOGGER.info("Starting rawscan of Bosch component")
            async_create_persistent_notification(
                self.hass,
                title="Bosch scan",
                message=("Starting rawscan"),
                notification_id=NOTIFICATION_ID,
            )
            rawscan = await self.gateway.rawscan()
            try:
                save_json(filename, rawscan)
            except (FileNotFoundError, OSError) as err:
                _LOGGER.error("Can't create file. %s", err)
                if rawscan:
                    return rawscan
            url = "{}{}{}".format(
                get_url(self.hass),
                "/local/bosch_scan.json?v",
                random.randint(0, 5000),
            )
            _LOGGER.info(f"Rawscan success. Your URL: {url}")
            async_create_persistent_notification(
                self.hass,
                title="Bosch scan",
                message=(f"[{url}]({url})"),
                notification_id=NOTIFICATION_ID,
            )
        return rawscan

    async def async_reset(self) -> bool:
        """Reset this device to default state."""
        _LOGGER.warning("Unloading Bosch module.")
        _LOGGER.debug("Closing connection to gateway.")
        tasks: list[Awaitable] = [
            self.hass.config_entries.async_forward_entry_unload(
                self.config_entry, platform
            )
            for platform in self.supported_platforms
        ]
        unload_ok = await asyncio.gather(*tasks)
        await self.gateway.close(force=False)
        return all(unload_ok)
