"""APPASSIONATA — passive TLS & HTTP header scanner.

Beethoven's *Piano Sonata No. 23* is all storm and insistence. Every host on
the internet declares the state of its transport loudly — the TLS version it
accepts, the headers it refuses to send, the cookies it forgets to guard.
APPASSIONATA is a *passive* listener: it connects once, reads what the host
announces, scores it, and ranks the storm.

Endpoints are probed with a single GET (plus redirects); that is active only
in the sense any browser is. No payloads, no scanning of ranges, no
content parsing.
"""

from __future__ import annotations

__version__ = "0.1.0"

BANNER = r"""
     _    ____  ____ _____ ____  ____  ____  _____ _____ ___  ____
    / \  |  _ \|  _ \_   _|  _ \/ ___||  _ \| ____|_   _/ _ \|  _ \
   / _ \ | |_) | |_) || | | |_) \___ \| |_) |  _|   | || | | | |_) |
  / ___ \|  __/|  __/ | | |  __/ ___) |  __/| |___  | || |_| |  _ <
 /_/   \_\_|   |_|    |_| |_|   |____/|_|   |_____| |_| \___/|_| \_\

  how loudly does your transport talk about you?
"""

__all__ = ["BANNER", "__version__"]
