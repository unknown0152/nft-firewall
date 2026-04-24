"""
src/core/profiles.py — Named firewall profile registry.

A profile provides the high-level policy flags that vary between deployments
(Cosmos ports, Plex LAN access, etc.).  The low-level network topology
(interface names, VPN endpoint, LAN subnet) comes from the INI config file
and is never stored here.

Usage
-----
    from core.profiles import get_profile, list_profiles

    profile = get_profile("cosmos-vpn-secure")
    print(profile.cosmos_tcp)   # [80, 443]

Adding a new profile
--------------------
Add an entry to :data:`PROFILES`.  No other file needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass(frozen=True)
class Profile:
    """Immutable policy flags for a named firewall profile.

    Attributes
    ----------
    description:
        One-line human-readable description shown by ``profiles`` command.
    cosmos_tcp:
        TCP ports used by Cosmos in ``--network host`` mode (no DNAT needed).
        Opened unconditionally in INPUT.
    cosmos_udp:
        UDP ports used by Cosmos Constellation VPN.
    allow_plex_lan:
        When ``True``, open port 32400 for LAN-only Plex direct play and
        drop it from all other sources.
    """

    description:    str
    cosmos_tcp:     List[int] = field(default_factory=list)
    cosmos_udp:     List[int] = field(default_factory=list)
    allow_plex_lan: bool      = False


# ── Profile registry ──────────────────────────────────────────────────────────

PROFILES: Dict[str, Profile] = {
    "cosmos-vpn-secure": Profile(
        description    = "Cosmos Cloud + full-tunnel VPN killswitch",
        cosmos_tcp     = [80, 443],
        cosmos_udp     = [4242],
        allow_plex_lan = True,
    ),
    "vpn-only": Profile(
        description    = "Pure VPN killswitch — no Cosmos, nothing extra",
        cosmos_tcp     = [],
        cosmos_udp     = [],
        allow_plex_lan = False,
    ),
    "media-vpn": Profile(
        description    = "Media stack + VPN killswitch + Cosmos proxy",
        cosmos_tcp     = [80, 443],
        cosmos_udp     = [],
        allow_plex_lan = True,
    ),
}


# ── Public helpers ────────────────────────────────────────────────────────────

def get_profile(name: str) -> Profile:
    """Return the :class:`Profile` for *name*.

    Parameters
    ----------
    name:
        Profile name, e.g. ``"cosmos-vpn-secure"``.

    Returns
    -------
    Profile

    Raises
    ------
    KeyError
        If *name* is not in :data:`PROFILES`, with a message listing the
        available names.
    """
    if name not in PROFILES:
        available = ", ".join(sorted(PROFILES))
        raise KeyError(
            f"Unknown profile {name!r}. Available profiles: {available}"
        )
    return PROFILES[name]


def list_profiles() -> Dict[str, Profile]:
    """Return the full profile registry (name → :class:`Profile`)."""
    return dict(PROFILES)
