"""Config flow to configure esphome component."""
import logging

import voluptuous as vol
from bosch_thermostat_client import gateway_chooser
from bosch_thermostat_client.const import HTTP, XMPP
from bosch_thermostat_client.const.easycontrol import EASYCONTROL
from bosch_thermostat_client.const.ivt import IVT, IVT_MBLAN
from bosch_thermostat_client.const.nefit import NEFIT
from bosch_thermostat_client.exceptions import (
    DeviceException,
    EncryptionException,
    FirmwareException,
    UnknownDevice,
)
from homeassistant import config_entries
from homeassistant.core import callback

from homeassistant.const import CONF_ACCESS_TOKEN, CONF_ADDRESS, CONF_PASSWORD
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from . import create_notification_firmware
from .const import (
    ACCESS_KEY,
    ACCESS_TOKEN,
    REFRESH_TOKEN,
    CONF_DEVICE_TYPE,
    CONF_DEVICE_ID,
    CONF_PROTOCOL,
    CONF_REFRESH_TOKEN,
    DOMAIN,
    POINTTAPI,
    UUID,
)

DEVICE_TYPE = [NEFIT, IVT, EASYCONTROL, IVT_MBLAN, POINTTAPI]
PROTOCOLS = [HTTP, XMPP, "OAUTH2"]


_LOGGER = logging.getLogger(__name__)


@config_entries.HANDLERS.register(DOMAIN)
class BoschFlowHandler(config_entries.ConfigFlow):
    """Handle a bosch config flow."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    def __init__(self):
        """Initialize Bosch flow."""
        self._choose_type = None
        self._host = None
        self._access_token = None
        self._password = None
        self._protocol = None
        self._device_type = None

    async def async_step_user(self, user_input=None):
        """Handle flow initiated by user."""
        return await self.async_step_choose_type(user_input)

    async def async_step_choose_type(self, user_input=None):
        """Choose if setup is for IVT, IVT/MBLAN, NEFIT, EASYCONTROL, or PoinTT API."""
        errors = {}
        if user_input is not None:
            self._choose_type = user_input[CONF_DEVICE_TYPE]
            if self._choose_type == POINTTAPI:
                return await self.async_step_pointt_oauth()
            elif self._choose_type == IVT:
                return self.async_show_form(
                    step_id="protocol",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_PROTOCOL): vol.All(
                                vol.Upper, vol.In(PROTOCOLS)
                            ),
                        }
                    ),
                    errors=errors,
                )
            elif self._choose_type in (NEFIT, EASYCONTROL, IVT_MBLAN):
                return await self.async_step_protocol({CONF_PROTOCOL: XMPP})
        return self.async_show_form(
            step_id="choose_type",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_TYPE): vol.All(
                        vol.Upper, vol.In(DEVICE_TYPE)
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_protocol(self, user_input=None):
        errors = {}
        if user_input is not None:
            self._protocol = user_input[CONF_PROTOCOL]
            # If OAuth2 is selected, go to OAuth setup instead of config form
            if self._protocol == "OAUTH2":
                return await self.async_step_oauth2_config()
            return self.async_show_form(
                step_id=f"{self._protocol.lower()}_config",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_ADDRESS): str,
                        vol.Required(CONF_ACCESS_TOKEN): str,
                        vol.Optional(CONF_PASSWORD): str,
                    }
                ),
                errors=errors,
            )
        return self.async_show_form(
            step_id="protocol",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PROTOCOL): vol.All(vol.Upper, vol.In(PROTOCOLS)),
                }
            ),
            errors=errors,
        )

    async def async_step_http_config(self, user_input=None):
        if user_input is not None:
            self._host = user_input[CONF_ADDRESS]
            self._access_token = user_input[CONF_ACCESS_TOKEN]
            self._password = user_input.get(CONF_PASSWORD)
            return await self.configure_gateway(
                device_type=self._choose_type,
                session=async_get_clientsession(self.hass, verify_ssl=False),
                session_type=self._protocol,
                host=self._host,
                access_token=self._access_token,
                password=self._password,
            )

    async def async_step_oauth2_config(self, user_input=None):
        """Handle OAuth2 configuration for IVT heat pump devices."""
        errors = {}
        if user_input is not None:
            device_id = user_input.get(CONF_DEVICE_ID)
            access_token = user_input.get(ACCESS_TOKEN)
            refresh_token = user_input.get(CONF_REFRESH_TOKEN)
            
            if not device_id or not access_token or not refresh_token:
                errors["base"] = "invalid_oauth_tokens"
            else:
                return await self.configure_gateway(
                    device_type=self._choose_type,
                    session_type="OAUTH2",
                    host=device_id,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )
        
        return self.async_show_form(
            step_id="oauth2_config",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_ID): str,
                    vol.Required(ACCESS_TOKEN): str,
                    vol.Required(CONF_REFRESH_TOKEN): str,
                }
            ),
            description_placeholders={
                "oauth_setup_url": "https://github.com/deric/bosch-thermostat-client-python/blob/k30/examples/pointtapi_oauth_setup.py",
            },
            errors=errors,
        )

    async def async_step_xmpp_config(self, user_input=None):
        if user_input is not None:
            self._host = user_input[CONF_ADDRESS]
            self._access_token = user_input[CONF_ACCESS_TOKEN]
            self._password = user_input.get(CONF_PASSWORD)
            if "127.0.0.1" in user_input[CONF_ADDRESS]:
                return await self.configure_gateway(
                    device_type=self._choose_type,
                    session=async_get_clientsession(self.hass, verify_ssl=False),
                    session_type=HTTP,
                    host=self._host,
                    access_token=self._access_token,
                    password=self._password,
                )
            return await self.configure_gateway(
                device_type=self._choose_type,
                session_type=self._protocol,
                host=self._host,
                access_token=self._access_token,
                password=self._password,
            )

    async def async_step_pointt_oauth(self, user_input=None):
        """Handle PoinTT API OAuth authentication."""
        errors = {}
        if user_input is not None:
            device_id = user_input.get(CONF_DEVICE_ID)
            access_token = user_input.get(ACCESS_TOKEN)
            refresh_token = user_input.get(CONF_REFRESH_TOKEN)
            
            if not device_id or not access_token or not refresh_token:
                errors["base"] = "invalid_oauth_tokens"
            else:
                return await self.configure_gateway(
                    device_type=self._choose_type,
                    session_type=HTTP,
                    host=device_id,
                    access_token=access_token,
                    refresh_token=refresh_token,
                )
        
        return self.async_show_form(
            step_id="pointt_oauth",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DEVICE_ID): str,
                    vol.Required(ACCESS_TOKEN): str,
                    vol.Required(CONF_REFRESH_TOKEN): str,
                }
            ),
            description_placeholders={
                "oauth_setup_url": "https://github.com/deric/bosch-thermostat-client-python/blob/k30/examples/pointtapi_oauth_setup.py",
            },
            errors=errors,
        )

    async def configure_gateway(
        self, device_type, session_type, host, access_token, password=None, session=None, refresh_token=None
    ):
        try:
            # If OAUTH2 protocol is selected, use Oauth2Gateway regardless of device_type
            if session_type == "OAUTH2":
                from bosch_thermostat_client.gateway.oauth2 import Oauth2Gateway
                BoschGateway = Oauth2Gateway
                _LOGGER.debug(f"Using Oauth2Gateway for device_type={device_type} with OAuth2 protocol")
            else:
                BoschGateway = gateway_chooser(device_type)
                _LOGGER.debug(f"Configuring gateway: device_type={device_type}, session_type={session_type}")
            
            # Create session early if needed
            if session is None and (device_type == POINTTAPI or session_type in (HTTP, "OAUTH2")):
                session = async_get_clientsession(self.hass, verify_ssl=False)
            
            # Build kwargs based on protocol/device type
            kwargs = {
                "host": host,
                "access_token": access_token,
            }
            
            # Add parameters based on protocol type
            if session_type == "OAUTH2":
                # OAuth2Gateway config
                kwargs["session"] = session
                kwargs["device_type"] = device_type
                if refresh_token is not None:
                    kwargs["refresh_token"] = refresh_token
            elif device_type == POINTTAPI:
                # Oauth2Gateway for K30/IVTAIR
                kwargs["session"] = session
                kwargs["device_type"] = device_type
                if refresh_token is not None:
                    kwargs["refresh_token"] = refresh_token
            else:
                # Other device types (IVT with HTTP/XMPP, NEFIT, EASYCONTROL)
                kwargs["session_type"] = session_type
                if session is not None:
                    kwargs["session"] = session
                if password is not None:
                    kwargs["password"] = password
            
            _LOGGER.debug(f"Gateway kwargs: {list(kwargs.keys())}")
            
            try:
                _LOGGER.debug(f"Attempting to create {BoschGateway.__name__} with kwargs: {list(kwargs.keys())}")
                device = BoschGateway(**kwargs)
                _LOGGER.debug(f"Gateway created successfully: {type(device).__name__}")
            except Exception as init_err:
                # Handle library validation errors (e.g., unsupported device)
                _LOGGER.error(f"Gateway creation failed with error: {init_err}")
                _LOGGER.error(f"Error type: {type(init_err).__name__}")
                import traceback
                _LOGGER.error(f"Full traceback: {traceback.format_exc()}")
                
                error_msg = str(init_err)
                if "not find supported device" in error_msg or "unsupported" in error_msg.lower():
                    _LOGGER.warning(f"Library device validation failed: {init_err}. Attempting to proceed anyway.")
                    # Try to create a minimal device object that can still work
                    try:
                        device = BoschGateway(**kwargs)
                        _LOGGER.debug(f"Gateway created on retry")
                    except Exception as retry_err:
                        _LOGGER.error(f"Failed to create gateway device on retry: {retry_err}")
                        return self.async_abort(reason="unsupported_device")
                else:
                    _LOGGER.error(f"Failed to initialize gateway: {init_err}")
                    return self.async_abort(reason="cannot_connect")
            
            uuid = None
            try:
                # For OAuth2, skip full check_connection to preserve refresh_token
                # But ensure device object has required attributes for config flow
                if session_type == "OAUTH2":
                    _LOGGER.debug("OAuth2 config flow: Skipping full connection check to preserve refresh_token")
                    uuid = host  # Use device_id as UUID for OAuth2
                    
                    # Ensure device has required attributes that config flow expects
                    if not hasattr(device, 'access_token'):
                        device.access_token = access_token
                    if not hasattr(device, 'uuid'):
                        device.uuid = uuid
                    
                    _LOGGER.debug(f"OAuth2 device configured - UUID: {uuid}")
                else:
                    _LOGGER.debug("Non-OAuth2 protocol: Performing full connection check")
                    uuid = await device.check_connection()
                    _LOGGER.debug(f"Device check_connection returned uuid: {uuid}")
                
                if not uuid:
                    _LOGGER.error("UUID is None or empty after device configuration")
                    return self.async_abort(reason="cannot_connect")
            except Exception as check_err:
                error_msg = str(check_err)
                if "not find supported device" in error_msg or "unsupported" in error_msg.lower():
                    _LOGGER.warning(f"Device validation error during check_connection: {check_err}. Attempting fallback.")
                    # Try to get UUID from API directly
                    try:
                        if hasattr(device, 'host') and device.host:
                            # Make direct HTTP request to get UUID
                            import aiohttp
                            direct_session = async_get_clientsession(self.hass, verify_ssl=False)
                            async with direct_session.get(f"http://{device.host}/gateway/uuid", timeout=10) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    uuid = data.get("value") or data.get("uuid")
                                    _LOGGER.debug(f"UUID from direct API call: {uuid}")
                    except Exception as api_err:
                        _LOGGER.debug(f"Direct API call failed: {api_err}")
                    
                    if not uuid:
                        uuid = getattr(device, 'uuid', None)
                        _LOGGER.debug(f"Using device.uuid from object: {uuid}")
                elif isinstance(check_err, (FirmwareException, UnknownDevice)):
                    _LOGGER.warning(f"Firmware or Unknown Device error: {check_err}")
                    create_notification_firmware(hass=self.hass, msg=check_err)
                    uuid = getattr(device, 'uuid', None)
                    _LOGGER.debug(f"Using device.uuid after FirmwareException: {uuid}")
                else:
                    _LOGGER.warning(f"Error during check_connection: {check_err}. Attempting to get UUID from device object.")
                    uuid = getattr(device, 'uuid', None)
                    _LOGGER.debug(f"UUID from device object: {uuid}")
            
            # For unknown/unsupported devices, try to get UUID from gateway info
            if not uuid:
                try:
                    # Attempt direct API call for gateway UUID
                    if hasattr(device, 'async_request'):
                        gateway_data = await device.async_request("get", "/gateway/uuid")
                        if gateway_data and isinstance(gateway_data, dict):
                            uuid = gateway_data.get("value") or gateway_data.get("uuid")
                        _LOGGER.debug(f"UUID from gateway API: {uuid}")
                except Exception as err:
                    _LOGGER.debug(f"Could not retrieve UUID from gateway API: {err}")
            
            if uuid and uuid != "-1":  # K30 may return "-1" as placeholder
                await self.async_set_unique_id(uuid)
                self._abort_if_unique_id_configured()
            elif uuid == "-1":
                # Use device serial number or host as fallback unique ID
                fallback_id = getattr(device, 'serial_number', None) or host or "bosch_unknown"
                _LOGGER.warning(f"Device returned placeholder UUID '-1', using fallback: {fallback_id}")
                await self.async_set_unique_id(fallback_id)
                self._abort_if_unique_id_configured()
                uuid = fallback_id
            else:
                _LOGGER.error(f"No UUID obtained from device")
                return self.async_abort(reason="unknown")
            
            _LOGGER.debug("Adding Bosch entry.")
            _LOGGER.info(f"[Config] Saving config entry with session_type={session_type}")
            data = {
                CONF_ADDRESS: host,  # Use input host instead of device.host in case device.host is not set
                UUID: uuid,
                ACCESS_TOKEN: device.access_token,
                CONF_DEVICE_TYPE: self._choose_type,
                CONF_PROTOCOL: session_type,
            }
            _LOGGER.info(f"[Config] Config entry data: CONF_DEVICE_TYPE={data[CONF_DEVICE_TYPE]}, CONF_PROTOCOL={data[CONF_PROTOCOL]}")
            # Fallback to host if device.host not available
            if hasattr(device, 'host') and device.host:
                data[CONF_ADDRESS] = device.host
            # access_key might not exist for Oauth2Gateway
            if hasattr(device, 'access_key') and device.access_key:
                data[ACCESS_KEY] = device.access_key
            if refresh_token is not None:
                data[CONF_REFRESH_TOKEN] = refresh_token
            
            # Capture refreshed tokens from the device connector after successful connection
            if hasattr(device, '_connector') and hasattr(device._connector, '_refresh_token'):
                fresh_refresh_token = getattr(device._connector, '_refresh_token', None)
                fresh_access_token = getattr(device._connector, '_access_token', None)
                if fresh_refresh_token and fresh_refresh_token != refresh_token:
                    _LOGGER.info("[Config Flow] Using refreshed tokens from successful connection")
                    data[CONF_REFRESH_TOKEN] = fresh_refresh_token
                    if fresh_access_token:
                        data[ACCESS_TOKEN] = fresh_access_token
            
            return self.async_create_entry(
                title=device.device_name or "Unknown model",
                data=data,
            )
        except (DeviceException, EncryptionException) as err:
            _LOGGER.error("Wrong IP or credentials at %s - %s", host, err)
            return self.async_abort(reason="faulty_credentials")
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.exception("Unexpected error connecting Bosch at %s", host)
            return self.async_abort(reason="unknown")

    async def async_step_discovery(self, discovery_info=None):
        """Handle a flow discovery."""
        _LOGGER.debug("Discovered Bosch unit : %s", discovery_info)

    @staticmethod
    @callback
    def async_get_options_flow(entry: config_entries.ConfigEntry):
        """Get option flow."""
        return OptionsFlowHandler(entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Options flow handler for new API."""

    def __init__(self, entry: config_entries.ConfigEntry):
        """Initialize option."""
        self.entry = entry

    async def async_step_init(self, user_input=None):
        """Display option dialog."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        new_stats_api = self.entry.options.get("new_stats_api", False)
        optimistic_mode = self.entry.options.get("optimistic_mode", False)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional("new_stats_api", default=new_stats_api): bool,
                    vol.Optional("optimistic_mode", default=optimistic_mode): bool,
                }
            ),
        )
