"""Implementation of dominionenergysc.com API."""

import dataclasses
import logging
import zoneinfo
from datetime import UTC, date, datetime
from typing import Any

import aiohttp
import xmltodict
from aiohttp.client_exceptions import ClientError, ClientResponseError

from .const import USER_AGENT
from .exceptions import ApiException, CannotConnect, InvalidAuth
from .utility import DominionSCUtility

_LOGGER = logging.getLogger(__file__)


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # units: Wh or Ft^3


@dataclasses.dataclass
class Forecast:
    """Forecast data for an account. Includes both electric and gas (where applicable)."""

    start_date: date
    end_date: date
    current_date: date
    cost_to_date: float
    forecasted_cost: float
    typical_cost: float


class DominionSC:
    """Class that can get historical and forecasted usage from an utility."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        utility: DominionSCUtility,
        username: str,
        password: str,
        login_data: dict[str, str] | None = None,  # {token: tfa_token}
    ) -> None:
        """Initialize."""
        # Note: Do not modify default headers since Home Assistant that uses this library needs to use
        # a default session for all integrations. Instead specify the headers for each request.
        self.session: aiohttp.ClientSession = session
        self.utility: DominionSCUtility = utility
        self.username: str = username
        self.password: str = password
        self.login_data: dict[str, str] = login_data or {}
        self.access_token: str | None = None
        self.user_id: str | None = None
        self.accounts: list[str] = []

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if we receive any HTTP error
        """
        try:
            self.access_token, self.user_id, self.accounts = await self.utility.async_login(
                self.session, self.username, self.password, self.login_data
            )
        except ClientResponseError as err:
            if err.status in (401, 403):
                raise InvalidAuth(err) from err
            raise CannotConnect(err) from err
        except ClientError as err:
            raise CannotConnect(err) from err

    async def async_get_accounts(self) -> list[str]:
        """Get a list of accounts for the signed in user."""
        return self.accounts

    def get_timezone(self) -> str:
        """Get the timezone used by the utility."""
        return self.utility.timezone

    async def async_get_forecast(self) -> list[Forecast]:
        """Get current and forecasted usage and cost for the current monthly bill.

        :raises InvalidAuth: if login information is incorrect
        """
        accounts = await self.async_get_accounts()
        if not accounts:
            raise InvalidAuth("User not logged in to retrieve async_get_forecast!")

        forecasted_data = await self.utility.async_get_forecast(self.session)

        return Forecast(
            start_date=forecasted_data["start_date"],
            end_date=forecasted_data["end_date"],
            current_date=forecasted_data["current_date"],
            cost_to_date=forecasted_data["cost_to_date"],
            forecasted_cost=forecasted_data["forecasted_cost"],
            typical_cost=forecasted_data["typical_cost"],
        )

    async def async_get_usage_reads(
        self,
        account: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[UsageRead]:
        """Get the usage reads from bidgely endpoint."""
        result: list[UsageRead] = []

        # Floor the dates to midnight UTC (how the API accepts data)
        start_date = datetime.combine(start_date, datetime.min.time())
        end_date = datetime.combine(end_date, datetime.min.time())
        start_time_timestamp = int(start_date.replace(tzinfo=zoneinfo.ZoneInfo("UTC")).timestamp())
        end_date_timestamp = int(end_date.replace(tzinfo=zoneinfo.ZoneInfo("UTC")).timestamp())
        url = (
            self.utility.bidgely_endpoint + f"/v2.0/dashboard/users/{self.user_id}/gb-download"
            f"?start={start_time_timestamp}&end={end_date_timestamp}"
            f"&measurement-type={account}&file-type=XML"
        )
        r = await self._async_get_request(url, self._get_headers())
        energy_usage = xmltodict.parse(r)

        for entry in energy_usage["feed"]["entry"]:
            if not entry["title"].startswith("Interval Consumption"):
                continue

            intervals = entry["content"]["espi:IntervalBlock"]["espi:IntervalReading"]
            # intervals_start_time = entry["content"]["espi:IntervalBlock"]["espi:interval"]["espi:start"]  # Day
            for interval in intervals:
                time_start = int(interval["espi:timePeriod"]["espi:start"])
                duration = int(interval["espi:timePeriod"]["espi:duration"])  # 900 sec (15 min) (electric) or 3600 (1hr) (gas)
                time_end = time_start + duration - 1
                consumption = int(interval["espi:value"])  # in Wh (electric) or ft^3 (gas)
                result.append(
                    UsageRead(
                        start_time=datetime.fromtimestamp(time_start, UTC).replace(
                            tzinfo=zoneinfo.ZoneInfo(self.utility.timezone)
                        ),
                        end_time=datetime.fromtimestamp(time_end, UTC).replace(
                            tzinfo=zoneinfo.ZoneInfo(self.utility.timezone)
                        ),
                        consumption=consumption,
                    )
                )
        return result

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": USER_AGENT,
            "IsAjax": "true",
            "X-Requested-With": "XMLHttpRequest",
            "Host": "desc-prodapi.bidgely.com",
            "Origin": "https://account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/",
            "X-Bidgely-Client-Type": "WIDGETS",
            "X-Bidgely-Pilot-Id": "10106",
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    async def _async_get_request(self, url: str, headers: dict[str, str]) -> Any:
        """Return the result of an api call."""
        try:
            async with self.session.get(url, headers=headers) as resp:
                result = await resp.text(encoding="utf-8")
        except ClientError as e:
            raise ApiException(f"Client Error: {e}", url=url) from e
        return result
