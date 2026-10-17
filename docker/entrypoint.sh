#!/bin/sh
set -eu

# Config saves contain device keys and login state as well as user settings.
umask 077
exec /usr/local/bin/corplink-rs-dev "$@"
