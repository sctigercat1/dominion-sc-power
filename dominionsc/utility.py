"""Base class that each utility needs to extend."""

# import abc
import json
import logging
import re
import time
from datetime import datetime
from typing import Any

import aiohttp

from .const import USER_AGENT
from .exceptions import CannotConnect, InvalidAuth, MfaChallenge

_LOGGER = logging.getLogger(__file__)


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
            raise ValueError("improper method for API call: {method}. must be get or post")

        try:
            async with api_func(url, json=json_data, headers=headers) as resp:
                result = await resp.text(encoding="utf-8")
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Failed to make an API call with error: {err}") from err
        return result


class DominionSCUtility:
    """Run main utility logic."""

    def __init__(self) -> None:
        """Initialize."""
        self._tfa_secret: str | None = None
        self._name: str = "Dominion Energy SC"
        self._dominion_endpoint: str = "https://account.dominionenergysc.com"
        self.bidgely_endpoint: str = "https://desc-prodapi.bidgely.com"
        self.timezone: str = "America/New_York"

    def _find_verification_token(self, webpage: str) -> str | None:
        try:
            token_search = re.findall(r'<input name="__RequestVerificationToken" type="hidden" value="(.*)" \/>', webpage)
            return token_search[0].split('" />', 1)[0]
        except Exception as err:
            raise CannotConnect("Cannot retrieve initial request verification token: {err}") from err

    async def async_login(
        self, session: aiohttp.ClientSession, username: str, password: str, login_data: dict[str, str] | None = None
    ) -> tuple[str, str, bool, bool | None]:
        """Login to the utility website.

        Return the access token or None

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if there is a retryable connection exception
        :raises aiohttp.ClientError: if there is a network error
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
        verification_token = self._find_verification_token(r0)

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
        r1_status = json.loads(r1)["data"]["status"]
        if r1_status != "twoFA":
            raise InvalidAuth(f"Error with login, possible invalid credentials: {r1_status}")

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
        verification_token = self._find_verification_token(r3)

        headers1["__RequestVerificationToken"] = verification_token
        headers1["Referer"] = "https://account.dominionenergysc.com/"
        del headers1["Origin"]

        tt = str(int(time.time() * 1000))
        url4 = self._dominion_endpoint + f"/fusionapi/AccountManagementWebApi/GetAccountListing/?_={tt}"
        r4 = await url_handler.call_api("get", url4, headers1)
        if json.loads(r4)["data"]["singleAccount"] is not True:
            raise InvalidAuth(f"User has multiple accounts, not currently implemented: {r4}")

        tt = str(int(time.time() * 1000))
        url5 = self._dominion_endpoint + f"/fusionapi/AccountSummaryWebApi/InitAccount/?_={tt}"
        r5 = await url_handler.call_api("get", url5, headers1)

        try:
            serviceAddressAndAccountNo = json.loads(r5)["data"]["account"]["serviceAddressAndAccountNo"]
        except Exception as err:
            raise InvalidAuth(f"Unable to init account ({err}): {r5}") from err

        tt = str(int(time.time() * 1000))
        url6 = self._dominion_endpoint + f"/fusionapi/BidgelyWebApi/GetBidgelySDKInit/?service=E&serviceAccountType=R&_={tt}"
        r6 = await url_handler.call_api("get", url6, headers1)
        try:
            encryptedToken = json.loads(r6)["data"]["payload"]
        except Exception as err:
            raise ValueError(f"unable to init bidgely ({err}): {r6}") from err

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
            raise InvalidAuth(f"unable to get accessToken or userId ({err}): {r7}") from err

        accounts = [[]]
        accounts.append(serviceAddressAndAccountNo)
        for dataTypes in json.loads(r7)["payload"]["userTypeDetails"]["measurementToUserTypeMappings"]:
            if dataTypes["measurementType"] in ["ELECTRIC", "GAS"]:
                accounts[0].append(dataTypes["measurementType"])

        return accessToken, userId, accounts

    async def async_get_forecast(self, session: aiohttp.ClientSession) -> dict[str, Any]:
        """Retrieve account AMI usage alerts with forecasted data.

        Return a dictionary with relevant data.

        :raises CannotConnect: if there is a retryable connection exception
        """
        url_handler = DominionSCURLHandler(session=session)

        headers0 = {
            "User-Agent": USER_AGENT,
            "Host": "account.dominionenergysc.com",
            "Referer": "https://account.dominionenergysc.com/access/",
        }

        r0 = await url_handler.call_api("get", self._dominion_endpoint + "/", headers0)
        verification_token = self._find_verification_token(r0)

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
            raise CannotConnect(f"Failed to get forecast data ({err}): {r1}") from err

        return {
            "start_date": start_date,
            "end_date": end_date,
            "current_date": current_date,
            "cost_to_date": cost_to_date,
            "forecasted_cost": forecasted_cost,
            "typical_cost": typical_cost,
        }


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
        _tfa_options = json.loads(r1)["data"]["userInfo"]
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
            raise CannotConnect(f"Error with TFA option selection: {r1}")

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
        if json.loads(r1)["data"]["isVerified"]:
            # tfa_token SUCCESS
            return {"tfa_token": json.loads(r1)["data"]["token"]}

        raise InvalidAuth(f"Bad TFA code: {r1}")
