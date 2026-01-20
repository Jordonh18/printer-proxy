"""
Single source of truth for application version.

Update this file to change the version everywhere.
The build script and templates read from here.
"""

__version__ = "2.0.0"
__version_info__ = tuple(int(x) for x in __version__.split("."))

# For display
VERSION_STRING = f"Printer Proxy v{__version__}"
