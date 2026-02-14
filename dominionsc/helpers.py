"""Helper functions."""

import aiohttp


def create_cookie_jar() -> aiohttp.CookieJar:
    """Create a cookie jar for DominionSC."""
    return aiohttp.CookieJar(quote_cookie=False)
