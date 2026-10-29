# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
"""Exception types raised by Sawone Red."""


class SawoneRedError(Exception):
    """Base class for all expected Sawone Red failures."""


class ConfigError(SawoneRedError):
    """The configuration or probe library is malformed."""


class AuthorizationError(SawoneRedError):
    """A real target was requested without a valid authorization block."""


class AdapterError(SawoneRedError):
    """A target could not be reached or returned an unusable reply."""
