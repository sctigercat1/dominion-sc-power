"""Implementation of dominionenergysc.com API."""

import dataclasses
import json
import logging
import re
import time
import zoneinfo
from datetime import UTC, date, datetime
from typing import Any

import aiohttp
import xmltodict
from aiohttp.client_exceptions import ClientError

from .const import USER_AGENT
from .exceptions import ApiException, CannotConnect, InvalidAuth, MfaChallenge

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


class DominionSCURLHandler:
    """Centralizes and handles all web communication."""

    def __init__(self, session: aiohttp.ClientSession):
        """Initialize the handler."""
        self._session = session

    async def call_api(
        self, method: str, url: str, headers: dict[str, str], json_data: dict[str, str] | None = None
    ) -> str | None:
        """Return the result of an api call."""
        api_func = None
        if method == "post":
            api_func = self._session.post
        elif method == "get":
            api_func = self._session.get
        else:
            raise ValueError(f"Improper method for API call: {method}. Must be GET or POST.")

        try:
            async with api_func(url, json=json_data, headers=headers) as resp:
                result = await resp.text(encoding="utf-8")
        except aiohttp.ClientError as err:
            raise CannotConnect(
                "Failed to make an API call due to network error.",
                url=url,
                status=getattr(err, "status", None),
                response_text=getattr(err, "text", None),
            ) from err
        return result


class DominionSCTFAHandler:
    """TFA Handler for utility."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        dominion_endpoint: str,
        headers: dict[str, str],
        url_handler: DominionSCURLHandler,
    ):
        """Initialize the TFA handler."""
        self._session = session
        self._dominion_endpoint: str = dominion_endpoint
        self._headers: dict[str, str] = headers
        self._url_handler: DominionSCURLHandler = url_handler
        self._tfa_options: dict[str, str] = {}

    async def async_get_tfa_options(self) -> dict[str, str]:
        """Return a dictionary of TFA options available to the user.

        The key is a stable identifier for the option, and the value is a
        user-friendly description (e.g., {"sms_1": "Text message to ******1234"}).

        The returned dictionary can be empty if no TFA options are available, i.e. the utility
        immediately asks for the code after login.
        """
        tfa_options: dict[str, str] = {}
        tt = str(int(time.time() * 1000))
        url1 = self._dominion_endpoint + f"/fusionapi/LoginWebApi/InitAuthentication/?_={tt}"
        r1 = await self._url_handler.call_api("get", url1, self._headers)
        try:
            _tfa_options = json.loads(r1)["data"]["userInfo"]
        except Exception as err:
            raise ApiException("Unable to decode InitAuthentication (TFA) userInfo", url=url1, response_text=r1) from err
        tfa_phone = _tfa_options["phoneNumbers"]
        tfa_email = _tfa_options["emailAddresses"]

        if tfa_phone:
            tfa_options[tfa_phone[0]] = tfa_phone[0]

        if tfa_email:
            tfa_options[tfa_email[0]] = tfa_email[0]

        self._tfa_options = tfa_options
        return tfa_options

    async def async_select_tfa_option(self, option_id: str) -> None:
        """Select an TFA option and trigger the code delivery.

        :raises CannotConnect: if the selection fails for reasons other than bad credentials.
        """
        _LOGGER.debug("Selecting TFA option %s", option_id)
        url1 = self._dominion_endpoint + "/fusionapi/LoginWebApi/SendPINCode/"
        data1 = {"sendMethod": option_id, "_df": ""}
        r1 = await self._url_handler.call_api("post", url1, self._headers, data1)
        if not json.loads(r1)["data"]:
            raise ApiException("Error with TFA option selection.", url=url1, response_text=r1)

        _LOGGER.debug("Successfully selected TFA option")

    async def async_submit_tfa_code(self, code: str) -> dict[str, str] | None:
        """Submit the user-provided code.

        On success, return login data that can be passed to async_login in order to skip TFA.
        On failure, raise InvalidAuth.

        :raises InvalidAuth: if the code is incorrect.
        """
        _LOGGER.debug("Submitting TFA code")

        url1 = self._dominion_endpoint + "/fusionapi/LoginWebApi/VerifyPIN/"
        data1 = {"PINcode": code, "registerDevice": True, "_df": ""}
        r1 = await self._url_handler.call_api("post", url1, self._headers, data1)
        try:
            if json.loads(r1)["data"]["isVerified"]:
                # tfa_token SUCCESS
                return {"tfa_token": json.loads(r1)["data"]["token"]}
        except Exception as err:
            raise ApiException("Unable to decode VerifyPIN isVerified", url=url1, response_text=r1) from err

        raise InvalidAuth(f"Invalid TFA code: {r1}")


class DominionSC:
    """Class that can get historical and forecasted usage from an utility."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, str] | None = None,  # {token: tfa_token}
    ) -> None:
        """Initialize."""
        # Note: Do not modify default headers since Home Assistant that uses this library needs to use
        # a default session for all integrations. Instead specify the headers for each request.
        self.session: aiohttp.ClientSession = session
        self.username: str = username
        self.password: str = password
        self.login_data: dict[str, str] = login_data or {}
        self.access_token: str | None = None
        self.user_id: str | None = None
        self.accounts: list[str] = []

        # Utility configuration (formerly in DominionSCUtility)
        self._tfa_secret: str | None = None
        self._name: str = "Dominion Energy SC"
        self._dominion_endpoint: str = "https://account.dominionenergysc.com"
        self.bidgely_endpoint: str = "https://desc-prodapi.bidgely.com"
        self.timezone: str = "America/New_York"

    def _find_verification_token(self, webpage: str, path: str, funct: str) -> str | None:
        """Find and extract the verification token from a webpage."""
        try:
            token_search = re.findall(r'<input name="__RequestVerificationToken" type="hidden" value="(.*)" \/>', webpage)
            return token_search[0].split('" />', 1)[0]
        except Exception as err:
            raise CannotConnect(f"Cannot retrieve request verification token (path={path}, funct={funct}).") from err

    async def async_login(self) -> None:
        """Login to the utility website and authorize for access.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if we receive any HTTP error
        :raises ApiException: if API response cannot be parsed (API structure may have changed)
        """
        try:
            self.access_token, self.user_id, self.accounts = await self._async_login_internal(
                self.session, self.username, self.password, self.login_data
            )
        except ClientError as err:
            raise CannotConnect(
                "Failed to connect to API",
                url=getattr(err, "url", None),
                status=getattr(err, "status", None),
                response_text=getattr(err, "text", None),
            ) from err

    async def _async_login_internal(
        self, session: aiohttp.ClientSession, username: str, password: str, login_data: dict[str, str] | None = None
    ) -> tuple[str, str, list | None]:
        """Login to the utility website.

        Return the access token or None

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if there is a retryable connection exception
        :raises ApiException: if API response cannot be parsed (API structure may have changed)
        """
        if login_data is None:
            login_data = {}  # {tfa_token: tfa_token}
        tfa_token: str = str(login_data.get("tfa_token", ""))

        url_handler = DominionSCURLHandler(session=session)

        # Load login page and retrieve verification token
        headers0 = {
            "User-Agent": USER_AGENT,
        }
        r0 = await url_handler.call_api("get", self._dominion_endpoint + "/access/#login", headers0)
        verification_token = self._find_verification_token(r0, "/access", "async_login")

        # Initial authentication test
        url1 = self._dominion_endpoint + "/fusionapi/LoginWebApi/Authenticate/"
        headers1 = {
            "User-Agent": USER_AGENT,
            "__RequestVerificationToken": verification_token,
            "IsAjax": "true",
            "X-Requested-With": "XMLHttpRequest",
            "Host": "account.dominionenergysc.com",
            "Origin": "https://account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/access/",
        }
        body = {"userName": username, "password": password, "_df": ""}
        r1 = await url_handler.call_api("post", url1, headers1, body)
        try:
            r1_status = json.loads(r1)["data"]["status"]
        except Exception as err:
            raise ApiException("Unable to decode Authenticate data status.", url=url1, response_text=r1) from err
        if r1_status == "failed":
            raise InvalidAuth(f"Invalid credentials, please try again. {r1}")
        if r1_status != "twoFA":
            raise InvalidAuth(
                "Unsuccessful authentication (possible no TFA required, please "
                f"report on github if you get this error): resp={r1}"
            )

        # TFA
        # Do we have a TFA token?
        if tfa_token != "":
            tt = str(int(time.time() * 1000))
            url2 = self._dominion_endpoint + f"/fusionapi/LoginWebApi/Verify2FAToken/?token={tfa_token}&_={tt}"
            r2 = await url_handler.call_api("get", url2, headers1)
            # Was token accepted?
            if not json.loads(r2)["data"]:
                tfa_token = None

        if not tfa_token:
            # Regenerate TFA token
            raise MfaChallenge(
                "Need new TFA token",
                DominionSCTFAHandler(session, self._dominion_endpoint, headers1, url_handler),
            )

        # Here we assume that the TFA token authorization was successful
        headers2 = {
            "User-Agent": USER_AGENT,
            "Host": "account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/access/",
        }

        r3 = await url_handler.call_api("get", self._dominion_endpoint + "/", headers2)
        verification_token = self._find_verification_token(r3, "/", "async_login")

        headers1["__RequestVerificationToken"] = verification_token
        headers1["Referer"] = "https://account.dominionenergysc.com/"
        del headers1["Origin"]

        tt = str(int(time.time() * 1000))
        url4 = self._dominion_endpoint + f"/fusionapi/AccountManagementWebApi/GetAccountListing/?_={tt}"
        r4 = await url_handler.call_api("get", url4, headers1)
        try:
            _ = json.loads(r4)["data"]["singleAccount"]
        except Exception as err:
            raise ApiException("Unable to decode GetAccountListing singleAccount.", url=url4, response_text=r4) from err
        if json.loads(r4)["data"]["singleAccount"] is not True:
            raise InvalidAuth(f"User has multiple accounts, not currently implemented (please report on github): {r4}")

        tt = str(int(time.time() * 1000))
        url5 = self._dominion_endpoint + f"/fusionapi/AccountSummaryWebApi/InitAccount/?_={tt}"
        r5 = await url_handler.call_api("get", url5, headers1)

        try:
            serviceAddressAndAccountNo = json.loads(r5)["data"]["account"]["serviceAddressAndAccountNo"]
        except Exception as err:
            raise ApiException("Unable to decode InitAccount serviceAddr.", url=url5, response_text=r5) from err

        tt = str(int(time.time() * 1000))
        url6 = self._dominion_endpoint + f"/fusionapi/BidgelyWebApi/GetBidgelySDKInit/?service=E&serviceAccountType=R&_={tt}"
        r6 = await url_handler.call_api("get", url6, headers1)
        try:
            encryptedToken = json.loads(r6)["data"]["payload"]
        except Exception as err:
            raise ApiException("Unable to decode GetBidgelySDKInit encToken", url=url6, response_text=r6) from err

        # Finally get bearer
        url7 = self.bidgely_endpoint + "/v2.0/web/wc-session"

        headers3 = {
            "User-Agent": USER_AGENT,
            "IsAjax": "true",
            "X-Requested-With": "XMLHttpRequest",
            "Host": "desc-prodapi.bidgely.com",
            "Origin": "https://account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/",
            "X-Bidgely-Client-Type": "WIDGETS",
            "X-Bidgely-Pilot-Id": "10106",
        }

        body2 = {"clientId": "prod_desc_widget", "encryptedData": encryptedToken}

        r7 = await url_handler.call_api("post", url7, headers3, body2)
        try:
            r7_json = json.loads(r7)
            accessToken = r7_json["payload"]["tokenDetails"]["accessToken"]
            userId = r7_json["payload"]["userProfileDetails"]["userId"]
        except Exception as err:
            raise ApiException("Unable to get accessToken or userId.", url=url7, response_text=r7) from err

        accounts = [[]]
        accounts.append(serviceAddressAndAccountNo)
        try:
            for dataTypes in json.loads(r7)["payload"]["userTypeDetails"]["measurementToUserTypeMappings"]:
                if dataTypes["measurementType"] in ["ELECTRIC", "GAS"]:
                    accounts[0].append(dataTypes["measurementType"])
        except Exception as err:
            raise ApiException("Unable to decode measurement type from wc-session.", url=url7, response_text=r7) from err

        return accessToken, userId, accounts

    async def async_get_accounts(self) -> list[str]:
        """Get a list of accounts for the signed in user."""
        return self.accounts

    def get_timezone(self) -> str:
        """Get the timezone used by the utility."""
        return self.timezone

    async def async_get_forecast(self) -> Forecast:
        """Get current and forecasted usage and cost for the current monthly bill.

        :raises InvalidAuth: if login information is incorrect
        :raises CannotConnect: if there is a retryable connection exception
        :raises ApiException: if API response cannot be parsed (API structure may have changed)
        """
        accounts = await self.async_get_accounts()
        if not accounts:
            raise InvalidAuth("User not logged in to retrieve async_get_forecast.")

        forecasted_data = await self._async_get_forecast_internal(self.session)

        return Forecast(
            start_date=forecasted_data["start_date"],
            end_date=forecasted_data["end_date"],
            current_date=forecasted_data["current_date"],
            cost_to_date=forecasted_data["cost_to_date"],
            forecasted_cost=forecasted_data["forecasted_cost"],
            typical_cost=forecasted_data["typical_cost"],
        )

    async def _async_get_forecast_internal(self, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Retrieve account AMI usage alerts with forecasted data.

        Return a dictionary with relevant data.

        :raises CannotConnect: if there is a retryable connection exception
        :raises ApiException: if API response cannot be parsed (API structure may have changed)
        """
        url_handler = DominionSCURLHandler(session=session)

        headers0 = {
            "User-Agent": USER_AGENT,
            "Host": "account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/access/",
        }

        r0 = await url_handler.call_api("get", self._dominion_endpoint + "/", headers0)
        verification_token = self._find_verification_token(r0, "/", "async_get_forecast")

        tt = str(int(time.time() * 1000))
        url1 = self._dominion_endpoint + f"/fusionapi/CommonWebApi/GetAccountAMIUsageAlerts/?_={tt}"
        headers1 = {
            "User-Agent": USER_AGENT,
            "__RequestVerificationToken": verification_token,
            "IsAjax": "true",
            "X-Requested-With": "XMLHttpRequest",
            "Host": "account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/",
        }
        r1 = await url_handler.call_api("get", url1, headers1)
        try:
            r1_json = json.loads(r1)
            start_date = datetime.fromisoformat(r1_json["data"]["amiUsageAlert"]["currentBillUsageStartDate"]).date()
            end_date = datetime.fromisoformat(r1_json["data"]["amiUsageAlert"]["currentBillUsageEndDate"]).date()
            current_date = datetime.fromisoformat(r1_json["data"]["amiUsageAlert"]["currentBillThroughDate"]).date()
            cost_to_date = r1_json["data"]["amiUsageAlert"]["totalCostUnbilledConsumption"]
            forecasted_cost = round(
                r1_json["data"]["amiUsageAlert"]["currentCostPerDay"]
                * r1_json["data"]["amiUsageAlert"]["numberOfDaysInCurrentBill"],
                2,
            )
            if r1_json["data"]["amiUsageAlert"]["lastYearAmountExists"]:
                typical_cost = r1_json["data"]["amiUsageAlert"]["lastYearTotalAmount"]
            else:
                typical_cost = None
        except Exception as err:
            raise ApiException("Failed to decode forecast data.", url=url1, response_text=r1) from err

        return {
            "start_date": start_date,
            "end_date": end_date,
            "current_date": current_date,
            "cost_to_date": cost_to_date,
            "forecasted_cost": forecasted_cost,
            "typical_cost": typical_cost,
        }

    async def async_get_usage_reads(
        self,
        account: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[UsageRead]:
        """Get the usage reads from bidgely endpoint.

        :raises CannotConnect: if there is a retryable connection exception
        :raises ApiException: if API response cannot be parsed (API structure may have changed)
        """
        result: list[UsageRead] = []

        # Floor the dates to midnight UTC (how the API accepts data)
        start_date = datetime.combine(start_date, datetime.min.time())
        end_date = datetime.combine(end_date, datetime.min.time())
        start_time_timestamp = int(start_date.replace(tzinfo=zoneinfo.ZoneInfo("UTC")).timestamp())
        end_date_timestamp = int(end_date.replace(tzinfo=zoneinfo.ZoneInfo("UTC")).timestamp())
        url = (
            self.bidgely_endpoint + f"/v2.0/dashboard/users/{self.user_id}/gb-download"
            f"?start={start_time_timestamp}&end={end_date_timestamp}"
            f"&measurement-type={account}&file-type=XML"
        )
        r = await self._async_get_request(url, self._get_headers())
        try:
            energy_usage = xmltodict.parse(r)

            for entry in energy_usage["feed"]["entry"]:
                if not entry["title"].startswith("Interval Consumption"):
                    continue

                intervals = entry["content"]["espi:IntervalBlock"]["espi:IntervalReading"]
                for interval in intervals:
                    time_start = int(interval["espi:timePeriod"]["espi:start"])
                    duration = int(
                        interval["espi:timePeriod"]["espi:duration"]
                    )  # 900 sec (15 min) (electric) or 3600 (1hr) (gas)
                    time_end = time_start + duration - 1
                    consumption = int(interval["espi:value"])  # in Wh (electric) or ft^3 (gas)
                    result.append(
                        UsageRead(
                            start_time=datetime.fromtimestamp(time_start, UTC).replace(
                                tzinfo=zoneinfo.ZoneInfo(self.timezone)
                            ),
                            end_time=datetime.fromtimestamp(time_end, UTC).replace(tzinfo=zoneinfo.ZoneInfo(self.timezone)),
                            consumption=consumption,
                        )
                    )
            return result
        except Exception as err:
            raise ApiException("Unable to parse XML in async_get_usage_reads.", url=url, response_text=r) from err

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
        except ClientError as err:
            raise CannotConnect(
                f"Failed to connect to API: {err}",
                url=url,
                status=getattr(err, "status", None),
                response_text=getattr(err, "text", None),
            ) from err
        return result
