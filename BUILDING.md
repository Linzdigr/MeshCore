# Get your custom firmware

```sh
# Needed for the build process
pipx install platformio

# List available build targets
sh build.sh list # Then choose the sufix needed (companion ble, repeater, etc.)

export FIRMWARE_VERSION=v1.17.1-scopes

# Finally, launch the build for the specific target.
sh build.sh build-firmware t1000e_companion_radio_ble

````