"""Support for Bosch Thermostat Climate."""
from __future__ import annotations
import logging
from typing import Any

from bosch_thermostat_client.const import HVAC_HEAT, HVAC_OFF, SETPOINT
from homeassistant.components.climate import ClimateEntity
from homeassistant.components.climate.const import (
    HVACAction,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.const import ATTR_TEMPERATURE
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .bosch_entity import BoschClimateWaterEntity
from .const import (
    BOSCH_STATE,
    CLIMATE,
    DOMAIN,
    GATEWAY,
    SIGNAL_BOSCH,
    SIGNAL_CLIMATE_UPDATE_BOSCH,
    SWITCHPOINT,
    UNITS_CONVERTER,
    UUID,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the Bosch thermostat from a config entry."""
    uuid = config_entry.data[UUID]
    data = hass.data[DOMAIN][uuid]
    optimistic_mode = config_entry.options.get("optimistic_mode", False)
    data[CLIMATE] = [
        BoschThermostat(
            hass=hass,
            uuid=uuid,
            bosch_object=hc,
            gateway=data[GATEWAY],
            optimistic_mode=optimistic_mode,
        )
        for hc in data[GATEWAY].heating_circuits
    ]
    async_add_entities(data[CLIMATE])
    async_dispatcher_send(hass, SIGNAL_BOSCH)
    return True


class BoschThermostat(BoschClimateWaterEntity, ClimateEntity):
    """Representation of a Bosch thermostat."""

    signal = SIGNAL_CLIMATE_UPDATE_BOSCH

    def __init__(
        self, hass, uuid, bosch_object, gateway, optimistic_mode: bool = False
    ) -> None:
        """Initialize the thermostat."""
        self._name_prefix = (
            "Zone circuit " if "/zones" in bosch_object.attr_id else "Heating circuit "
        )
        self._mode = {}
        self._hvac_modes = []
        self._hvac_mode = None
        self._optimistic_mode = optimistic_mode
        self._is_enabled = True

        super().__init__(
            hass=hass, uuid=uuid, bosch_object=bosch_object, gateway=gateway
        )
        
        # Initialize modes from bosch object immediately
        try:
            self._hvac_modes = self._bosch_object.ha_modes or []
            self._hvac_mode = self._bosch_object.ha_mode
            _LOGGER.debug(
                "HC %s initialized with modes: %s, current_mode: %s",
                self._name, self._hvac_modes, self._hvac_mode
            )
        except (AttributeError, Exception) as err:
            _LOGGER.warning("Could not initialize modes for %s: %s", self._name, err)
            self._hvac_modes = []
            self._hvac_mode = None

    @property
    def state_attributes(self) -> dict[str, Any]:
        """Attributes of entity."""
        data = super().state_attributes
        try:
            data[SETPOINT] = self._bosch_object.setpoint
            if self._bosch_object.schedule:
                data[SWITCHPOINT] = self._bosch_object.schedule.active_program
            data[BOSCH_STATE] = self._state
            # Add current operation mode (MANUAL, AUTO, etc.)
            try:
                data['operation_mode'] = self._bosch_object._op_mode.current_mode
            except (AttributeError, TypeError):
                pass
            if self._bosch_object.extra_state_attributes:
                data = {**data, **self._bosch_object.extra_state_attributes}
        except NotImplementedError:
            pass
        return data

    @property
    def supported_features(self):
        """Return the list of supported features."""
        features = ClimateEntityFeature.TARGET_TEMPERATURE
        
        # Add HVAC mode support if modes are available
        if self._hvac_modes and len(self._hvac_modes) > 0:
            features |= ClimateEntityFeature.TURN_ON
            features |= ClimateEntityFeature.TURN_OFF
        
        # Add preset mode support if available
        if self._bosch_object.support_presets:
            features |= ClimateEntityFeature.PRESET_MODE
        
        _LOGGER.debug(
            "HC %s supported features: %s, modes: %s",
            self._name, features, self._hvac_modes
        )
        return features

    async def async_set_hvac_mode(self, hvac_mode):
        """Set operation mode."""
        _LOGGER.debug(f"Setting operation mode {hvac_mode}.")

        if self._optimistic_mode:
            _old_hvac_mode = self._bosch_object.ha_mode
            self._hvac_mode = hvac_mode
            self.schedule_update_ha_state()
        status = await self._bosch_object.set_ha_mode(hvac_mode)
        if status > 0:
            return True
        if self._optimistic_mode:
            """If fail revert back to mode it was back then."""
            self._hvac_mode = _old_hvac_mode
            self.schedule_update_ha_state()
        return False

    async def async_set_temperature(self, **kwargs):
        """Set new target temperature."""
        temperature = kwargs.get(ATTR_TEMPERATURE)
        if temperature is None:
            _LOGGER.error("No target temperature provided")
            return
        
        # Validate temperature is within limits
        if temperature < self.min_temp or temperature > self.max_temp:
            _LOGGER.error(f"Temperature {temperature}°C out of range [{self.min_temp}-{self.max_temp}]")
            return
        
        _LOGGER.info(
            "Setting %s target temperature from %.1f°C to %.1f°C",
            self._name,
            self._current_temperature if self._current_temperature else 0,
            temperature
        )
        try:
            result = await self._bosch_object.set_temperature(temperature)
            if result:
                _LOGGER.info("Temperature set successfully for %s", self._name)
                if self._optimistic_mode:
                    self._target_temperature = temperature
                    self.schedule_update_ha_state()
            else:
                _LOGGER.warning("Temperature set returned False for %s", self._name)
        except Exception as err:
            _LOGGER.error(f"Error setting temperature for {self._name}: {err}")

    @property
    def hvac_mode(self):
        """Return current operation ie. heat, cool, idle."""
        return self._hvac_mode

    @property
    def hvac_action(self):
        """Hvac action."""
        hvac_action = self._bosch_object.hvac_action
        if hvac_action == HVAC_HEAT:
            return HVACAction.HEATING
        if hvac_action == HVAC_OFF:
            return HVACAction.IDLE

    @property
    def hvac_modes(self) -> list:
        """List of available operation modes."""
        return self._hvac_modes

    @property
    def preset_modes(self):
        """Return available preset modes."""
        try:
            return self._bosch_object.preset_modes
        except (AttributeError, KeyError, TypeError):
            # If preset modes not available, return empty list
            return []

    @property
    def preset_mode(self):
        """Return current preset mode."""
        try:
            return self._bosch_object.preset_mode
        except (AttributeError, KeyError, TypeError):
            return None

    async def async_set_preset_mode(self, preset_mode):
        """Set new target preset mode."""
        await self._bosch_object.set_preset_mode(preset_mode)

    async def async_update(self):
        """Update state of device."""
        _LOGGER.debug("Update of climate %s component called.", self._name)
        if not self._bosch_object or not self._bosch_object.update_initialized:
            return
        self._temperature_units = UNITS_CONVERTER.get(self._bosch_object.temp_units)
        if (
            self._state != self._bosch_object.state
            or self._target_temperature != self._bosch_object.target_temperature
            or self._current_temperature != self._bosch_object.current_temp
            or self._hvac_modes != self._bosch_object.ha_modes
            or self._hvac_mode != self._bosch_object.ha_mode
        ):
            self._state = self._bosch_object.state
            self._target_temperature = self._bosch_object.target_temperature
            self._current_temperature = self._bosch_object.current_temp
            self._hvac_modes = self._bosch_object.ha_modes
            self._hvac_mode = self._bosch_object.ha_mode
            _LOGGER.debug(
                "HC %s updated: state=%s, current_temp=%.1f°C, target_temp=%.1f°C, mode=%s, available_modes=%s",
                self._name,
                self._state,
                self._current_temperature if self._current_temperature else 0,
                self._target_temperature if self._target_temperature else 0,
                self._hvac_mode,
                self._hvac_modes
            )
            self.async_schedule_update_ha_state()
