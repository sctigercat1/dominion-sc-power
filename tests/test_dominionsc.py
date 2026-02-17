"""Tests for dominionsc module."""

import json
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
import pytest
from aiohttp.client_exceptions import ClientError, ClientResponseError

from dominionsc.const import USER_AGENT
from dominionsc.dominionsc import DominionSC, DominionSCTFAHandler, DominionSCURLHandler, Forecast, UsageRead
from dominionsc.exceptions import ApiException, CannotConnect, InvalidAuth, MfaChallenge


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    session = Mock(spec=aiohttp.ClientSession)
    return session


@pytest.fixture
def dominion_client(mock_session):
    """Create a DominionSC client for testing."""
    return DominionSC(
        session=mock_session,
        username="test_user",
        password="test_pass",
        login_data={"token": "test_token"},
    )


class TestUsageRead:
    """Tests for UsageRead dataclass."""

    def test_usage_read_creation(self):
        """Test creating a UsageRead."""
        start = datetime(2025, 2, 1, 0, 0, 0, tzinfo=UTC)
        end = datetime(2025, 2, 1, 0, 15, 0, tzinfo=UTC)
        consumption = 500.0

        usage = UsageRead(start_time=start, end_time=end, consumption=consumption)

        assert usage.start_time == start
        assert usage.end_time == end
        assert usage.consumption == consumption


class TestForecast:
    """Tests for Forecast dataclass."""

    def test_forecast_creation(self):
        """Test creating a Forecast."""
        forecast = Forecast(
            start_date=date(2025, 2, 1),
            end_date=date(2025, 2, 28),
            current_date=date(2025, 2, 15),
            cost_to_date=125.50,
            forecasted_cost=250.00,
            typical_cost=240.00,
        )

        assert forecast.start_date == date(2025, 2, 1)
        assert forecast.end_date == date(2025, 2, 28)
        assert forecast.current_date == date(2025, 2, 15)
        assert forecast.cost_to_date == 125.50
        assert forecast.forecasted_cost == 250.00
        assert forecast.typical_cost == 240.00


class TestDominionSCURLHandler:
    """Tests for DominionSCURLHandler class."""

    @pytest.fixture
    def handler(self, mock_session):
        """Create a URL handler."""
        return DominionSCURLHandler(mock_session)

    def test_initialization(self, mock_session):
        """Test handler initialization."""
        handler = DominionSCURLHandler(mock_session)
        assert handler._session is mock_session

    @pytest.mark.asyncio
    async def test_call_api_post_success(self, handler, mock_session):
        """Test successful POST API call."""
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="response text")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session.post = Mock(return_value=mock_response)

        result = await handler.call_api(
            "post",
            "https://test.com/api",
            {"User-Agent": "test"},
            {"key": "value"},
        )

        assert result == "response text"
        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_api_get_success(self, handler, mock_session):
        """Test successful GET API call."""
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="get response")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        mock_session.get = Mock(return_value=mock_response)

        result = await handler.call_api(
            "get",
            "https://test.com/api",
            {"User-Agent": "test"},
        )

        assert result == "get response"
        mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_call_api_invalid_method(self, handler):
        """Test API call with invalid method."""
        with pytest.raises(ValueError, match="Improper method"):
            await handler.call_api(
                "delete",
                "https://test.com",
                {},
            )

    @pytest.mark.asyncio
    async def test_call_api_client_error(self, handler, mock_session):
        """Test API call with client error."""
        mock_session.get = Mock(side_effect=aiohttp.ClientError("Network error"))

        with pytest.raises(CannotConnect, match="Failed to make an API call"):
            await handler.call_api("get", "https://test.com", {})


class TestDominionSCTFAHandler:
    """Tests for DominionSCTFAHandler class."""

    @pytest.fixture
    def mock_url_handler(self):
        """Create a mock URL handler."""
        return Mock(spec=DominionSCURLHandler)

    @pytest.fixture
    def tfa_handler(self, mock_session, mock_url_handler):
        """Create a TFA handler."""
        return DominionSCTFAHandler(
            mock_session,
            "https://account.dominionenergysc.com",
            {"User-Agent": USER_AGENT},
            mock_url_handler,
        )

    def test_initialization(self, tfa_handler, mock_session, mock_url_handler):
        """Test TFA handler initialization."""
        assert tfa_handler._session is mock_session
        assert tfa_handler._dominion_endpoint == "https://account.dominionenergysc.com"
        assert tfa_handler._headers == {"User-Agent": USER_AGENT}
        assert tfa_handler._url_handler is mock_url_handler
        assert tfa_handler._tfa_options == {}

    @pytest.mark.asyncio
    async def test_async_get_tfa_options_phone_only(self, tfa_handler, mock_url_handler):
        """Test getting TFA options with phone only."""
        response = json.dumps(
            {
                "data": {
                    "userInfo": {
                        "phoneNumbers": ["***-***-1234"],
                        "emailAddresses": [],
                    }
                }
            }
        )
        mock_url_handler.call_api = AsyncMock(return_value=response)

        options = await tfa_handler.async_get_tfa_options()

        assert options == {"***-***-1234": "***-***-1234"}
        assert tfa_handler._tfa_options == options

    @pytest.mark.asyncio
    async def test_async_get_tfa_options_email_only(self, tfa_handler, mock_url_handler):
        """Test getting TFA options with email only."""
        response = json.dumps(
            {
                "data": {
                    "userInfo": {
                        "phoneNumbers": [],
                        "emailAddresses": ["test@example.com"],
                    }
                }
            }
        )
        mock_url_handler.call_api = AsyncMock(return_value=response)

        options = await tfa_handler.async_get_tfa_options()

        assert options == {"test@example.com": "test@example.com"}

    @pytest.mark.asyncio
    async def test_async_get_tfa_options_both(self, tfa_handler, mock_url_handler):
        """Test getting TFA options with both phone and email."""
        response = json.dumps(
            {
                "data": {
                    "userInfo": {
                        "phoneNumbers": ["***-***-1234"],
                        "emailAddresses": ["test@example.com"],
                    }
                }
            }
        )
        mock_url_handler.call_api = AsyncMock(return_value=response)

        options = await tfa_handler.async_get_tfa_options()

        assert len(options) == 2
        assert "***-***-1234" in options
        assert "test@example.com" in options

    @pytest.mark.asyncio
    async def test_async_get_tfa_options_empty(self, tfa_handler, mock_url_handler):
        """Test getting TFA options when none available."""
        response = json.dumps(
            {
                "data": {
                    "userInfo": {
                        "phoneNumbers": [],
                        "emailAddresses": [],
                    }
                }
            }
        )
        mock_url_handler.call_api = AsyncMock(return_value=response)

        options = await tfa_handler.async_get_tfa_options()

        assert options == {}

    @pytest.mark.asyncio
    async def test_async_select_tfa_option_success(self, tfa_handler, mock_url_handler):
        """Test successful TFA option selection."""
        response = json.dumps({"data": True})
        mock_url_handler.call_api = AsyncMock(return_value=response)

        await tfa_handler.async_select_tfa_option("***-***-1234")

        mock_url_handler.call_api.assert_called_once()
        call_args = mock_url_handler.call_api.call_args
        assert call_args[0][0] == "post"
        assert "SendPINCode" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_async_select_tfa_option_failure(self, tfa_handler, mock_url_handler):
        """Test TFA option selection failure."""
        response = json.dumps({"data": False})
        mock_url_handler.call_api = AsyncMock(return_value=response)

        with pytest.raises(ApiException, match="Error with TFA option selection"):
            await tfa_handler.async_select_tfa_option("invalid_option")

    @pytest.mark.asyncio
    async def test_async_submit_tfa_code_success(self, tfa_handler, mock_url_handler):
        """Test successful TFA code submission."""
        response = json.dumps({"data": {"isVerified": True, "token": "tfa_token_123"}})
        mock_url_handler.call_api = AsyncMock(return_value=response)

        result = await tfa_handler.async_submit_tfa_code("123456")

        assert result == {"tfa_token": "tfa_token_123"}

    @pytest.mark.asyncio
    async def test_async_submit_tfa_code_invalid(self, tfa_handler, mock_url_handler):
        """Test TFA code submission with invalid code."""
        response = json.dumps({"data": {"isVerified": False}})
        mock_url_handler.call_api = AsyncMock(return_value=response)

        with pytest.raises(InvalidAuth, match="Invalid TFA code"):
            await tfa_handler.async_submit_tfa_code("wrong_code")

    @pytest.mark.asyncio
    async def test_async_submit_tfa_code_calls_correct_endpoint(self, tfa_handler, mock_url_handler):
        """Test that submit TFA code calls the correct endpoint."""
        response = json.dumps({"data": {"isVerified": True, "token": "token"}})
        mock_url_handler.call_api = AsyncMock(return_value=response)

        await tfa_handler.async_submit_tfa_code("123456")

        call_args = mock_url_handler.call_api.call_args
        assert call_args[0][0] == "post"
        assert "VerifyPIN" in call_args[0][1]
        json_data = call_args[0][3]
        assert json_data["PINcode"] == "123456"
        assert json_data["registerDevice"] is True

    @pytest.mark.asyncio
    async def test_async_get_tfa_options_json_error(self, tfa_handler, mock_url_handler):
        """Test getting TFA options with JSON decode error."""
        response = "This is not JSON"
        mock_url_handler.call_api = AsyncMock(return_value=response)

        with pytest.raises(ApiException, match="Unable to decode InitAuthentication"):
            await tfa_handler.async_get_tfa_options()

    @pytest.mark.asyncio
    async def test_async_submit_tfa_code_json_error(self, tfa_handler, mock_url_handler):
        """Test submit TFA code with JSON decode error."""
        response = "This is not JSON"
        mock_url_handler.call_api = AsyncMock(return_value=response)

        with pytest.raises(ApiException, match="Unable to decode VerifyPIN"):
            await tfa_handler.async_submit_tfa_code("123456")


class TestDominionSC:
    """Tests for DominionSC class."""

    def test_init_default_login_data(self, mock_session):
        """Test initialization with default login_data."""
        client = DominionSC(
            session=mock_session,
            username="user",
            password="pass",
        )

        assert client.session == mock_session
        assert client.username == "user"
        assert client.password == "pass"
        assert client.login_data == {}
        assert client.access_token is None
        assert client.user_id is None
        assert client.accounts == []
        assert client.timezone == "America/New_York"
        assert client.bidgely_endpoint == "https://desc-prodapi.bidgely.com"
        assert client._dominion_endpoint == "https://account.dominionenergysc.com"

    def test_init_with_login_data(self, dominion_client):
        """Test initialization with login_data."""
        assert dominion_client.login_data == {"token": "test_token"}

    @pytest.mark.asyncio
    async def test_async_login_success(self, dominion_client):
        """Test successful login."""
        with patch.object(
            dominion_client,
            "_async_login_internal",
            new=AsyncMock(return_value=("access_123", "user_456", ["account1", "account2"])),
        ):
            await dominion_client.async_login()

        assert dominion_client.access_token == "access_123"
        assert dominion_client.user_id == "user_456"
        assert dominion_client.accounts == ["account1", "account2"]

    @pytest.mark.asyncio
    async def test_async_login_invalid_auth_401(self, dominion_client):
        """Test login with 401 error raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=401,
            message="Unauthorized",
        )
        with patch.object(
            dominion_client,
            "_async_login_internal",
            new=AsyncMock(side_effect=error),
        ):
            with pytest.raises(CannotConnect):
                await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_invalid_auth_403(self, dominion_client):
        """Test login with 403 error raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=403,
            message="Forbidden",
        )
        with patch.object(
            dominion_client,
            "_async_login_internal",
            new=AsyncMock(side_effect=error),
        ):
            with pytest.raises(CannotConnect):
                await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_client_error(self, dominion_client):
        """Test login with ClientError raises CannotConnect."""
        error = ClientError("Connection failed")
        with patch.object(
            dominion_client,
            "_async_login_internal",
            new=AsyncMock(side_effect=error),
        ):
            with pytest.raises(CannotConnect):
                await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_internal_full_flow_success(self, dominion_client):
        """Test complete login flow with valid TFA token."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',  # r0
            '{"data": {"status": "twoFA"}}',  # r1
            '{"data": true}',  # r2 - TFA token valid
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',  # r3
            '{"data": {"singleAccount": true}}',  # r4
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',  # r5
            '{"data": {"payload": "encrypted_token"}}',  # r6
            '{"payload": {"tokenDetails": {"accessToken": "access123"}, "userProfileDetails": {"userId": "user456"}, "userTypeDetails": {"measurementToUserTypeMappings": [{"measurementType": "ELECTRIC"}]}}}',  # r7
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            access_token, user_id, accounts = await dominion_client._async_login_internal(
                dominion_client.session,
                "test_user",
                "test_pass",
                {"tfa_token": "valid_tfa_token"},
            )

        assert access_token == "access123"
        assert user_id == "user456"
        assert "ELECTRIC" in accounts[0]

    @pytest.mark.asyncio
    async def test_async_login_internal_failed_credentials(self, dominion_client):
        """Test login with failed credentials."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "failed"}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="Invalid credentials"):
                await dominion_client._async_login_internal(dominion_client.session, "bad_user", "bad_pass")

    @pytest.mark.asyncio
    async def test_async_login_internal_unexpected_status(self, dominion_client):
        """Test login with unexpected auth status."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "locked"}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="Unsuccessful authentication"):
                await dominion_client._async_login_internal(dominion_client.session, "test_user", "test_pass")

    @pytest.mark.asyncio
    async def test_async_login_internal_invalid_tfa_token(self, dominion_client):
        """Test login with invalid TFA token raises MfaChallenge."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": false}',  # Invalid TFA token
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(MfaChallenge, match="Need new TFA token"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "invalid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_no_tfa_token(self, dominion_client):
        """Test login without TFA token raises MfaChallenge."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(MfaChallenge):
                await dominion_client._async_login_internal(dominion_client.session, "test_user", "test_pass")

    @pytest.mark.asyncio
    async def test_async_login_internal_multiple_accounts(self, dominion_client):
        """Test login with multiple accounts error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": false}}',  # Multiple accounts
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="multiple accounts"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_api_errors(self, dominion_client):
        """Test login with various API decode errors."""
        # Test error decoding authenticate status
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {}}',  # Missing status
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode Authenticate data status"):
                await dominion_client._async_login_internal(dominion_client.session, "test_user", "test_pass")

    @pytest.mark.asyncio
    async def test_async_login_internal_account_listing_error(self, dominion_client):
        """Test login with account listing decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {}}',  # Missing singleAccount
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode GetAccountListing"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_init_account_error(self, dominion_client):
        """Test login with InitAccount decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {}}',  # Missing account info
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode InitAccount"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_bidgely_token_error(self, dominion_client):
        """Test login with Bidgely token decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {}}',  # Missing payload
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode GetBidgelySDKInit"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_access_token_error(self, dominion_client):
        """Test login with access token decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {"payload": "encrypted_token"}}',
            '{"payload": {}}',  # Missing tokenDetails
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to get accessToken"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_measurement_type_error(self, dominion_client):
        """Test login with measurement type decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {"payload": "encrypted_token"}}',
            '{"payload": {"tokenDetails": {"accessToken": "access123"}, "userProfileDetails": {"userId": "user456"}, "userTypeDetails": {}}}',  # Missing measurementToUserTypeMappings
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode measurement type"):
                await dominion_client._async_login_internal(
                    dominion_client.session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_internal_with_gas_account(self, dominion_client):
        """Test login returns both ELECTRIC and GAS accounts."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {"payload": "encrypted_token"}}',
            '{"payload": {"tokenDetails": {"accessToken": "access123"}, "userProfileDetails": {"userId": "user456"}, "userTypeDetails": {"measurementToUserTypeMappings": [{"measurementType": "ELECTRIC"}, {"measurementType": "GAS"}]}}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            access_token, user_id, accounts = await dominion_client._async_login_internal(
                dominion_client.session,
                "test_user",
                "test_pass",
                {"tfa_token": "valid_token"},
            )

        assert "ELECTRIC" in accounts[0]
        assert "GAS" in accounts[0]

    @pytest.mark.asyncio
    async def test_async_get_accounts(self, dominion_client):
        """Test getting accounts."""
        dominion_client.accounts = ["account1", "account2"]

        accounts = await dominion_client.async_get_accounts()

        assert accounts == ["account1", "account2"]

    def test_get_timezone(self, dominion_client):
        """Test getting timezone."""
        timezone = dominion_client.get_timezone()

        assert timezone == "America/New_York"

    @pytest.mark.asyncio
    async def test_async_get_forecast_success(self, dominion_client):
        """Test successful forecast retrieval."""
        dominion_client.accounts = ["account1"]

        with patch.object(
            dominion_client,
            "_async_get_forecast_internal",
            new=AsyncMock(
                return_value={
                    "start_date": date(2025, 2, 1),
                    "end_date": date(2025, 2, 28),
                    "current_date": date(2025, 2, 15),
                    "cost_to_date": 100.0,
                    "forecasted_cost": 200.0,
                    "typical_cost": 195.0,
                }
            ),
        ):
            forecast = await dominion_client.async_get_forecast()

        assert isinstance(forecast, Forecast)
        assert forecast.start_date == date(2025, 2, 1)
        assert forecast.end_date == date(2025, 2, 28)
        assert forecast.current_date == date(2025, 2, 15)
        assert forecast.cost_to_date == 100.0
        assert forecast.forecasted_cost == 200.0
        assert forecast.typical_cost == 195.0

    @pytest.mark.asyncio
    async def test_async_get_forecast_not_logged_in(self, dominion_client):
        """Test forecast retrieval when not logged in."""
        dominion_client.accounts = []

        with pytest.raises(InvalidAuth, match="User not logged in"):
            await dominion_client.async_get_forecast()

    @pytest.mark.asyncio
    async def test_async_get_forecast_internal_success(self, dominion_client):
        """Test internal forecast method with successful response."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"amiUsageAlert": {"currentBillUsageStartDate": "2025-02-01", "currentBillUsageEndDate": "2025-02-28", "currentBillThroughDate": "2025-02-15", "totalCostUnbilledConsumption": 100.0, "currentCostPerDay": 7.14, "numberOfDaysInCurrentBill": 28, "lastYearAmountExists": true, "lastYearTotalAmount": 195.0}}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            result = await dominion_client._async_get_forecast_internal(dominion_client.session)

        assert result["start_date"] == date(2025, 2, 1)
        assert result["end_date"] == date(2025, 2, 28)
        assert result["current_date"] == date(2025, 2, 15)
        assert result["cost_to_date"] == 100.0
        assert result["forecasted_cost"] == 199.92
        assert result["typical_cost"] == 195.0

    @pytest.mark.asyncio
    async def test_async_get_forecast_internal_no_typical_cost(self, dominion_client):
        """Test forecast when typical cost is not available."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"amiUsageAlert": {"currentBillUsageStartDate": "2025-02-01", "currentBillUsageEndDate": "2025-02-28", "currentBillThroughDate": "2025-02-15", "totalCostUnbilledConsumption": 100.0, "currentCostPerDay": 7.14, "numberOfDaysInCurrentBill": 28, "lastYearAmountExists": false}}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            result = await dominion_client._async_get_forecast_internal(dominion_client.session)

        assert result["typical_cost"] is None

    @pytest.mark.asyncio
    async def test_async_get_forecast_internal_decode_error(self, dominion_client):
        """Test forecast with decode error."""
        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {}}',  # Missing amiUsageAlert
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Failed to decode forecast data"):
                await dominion_client._async_get_forecast_internal(dominion_client.session)

    @pytest.mark.asyncio
    async def test_async_get_usage_reads_success(self, dominion_client):
        """Test successful usage reads retrieval."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<feed>
    <entry>
        <title>Interval Consumption Data</title>
        <content>
            <espi:IntervalBlock>
                <espi:interval>
                    <espi:start>1706745600</espi:start>
                </espi:interval>
                <espi:IntervalReading>
                    <espi:timePeriod>
                        <espi:start>1706745600</espi:start>
                        <espi:duration>900</espi:duration>
                    </espi:timePeriod>
                    <espi:value>500</espi:value>
                </espi:IntervalReading>
                <espi:IntervalReading>
                    <espi:timePeriod>
                        <espi:start>1706746500</espi:start>
                        <espi:duration>900</espi:duration>
                    </espi:timePeriod>
                    <espi:value>600</espi:value>
                </espi:IntervalReading>
            </espi:IntervalBlock>
        </content>
    </entry>
    <entry>
        <title>Other Data</title>
        <content>Not interval consumption</content>
    </entry>
</feed>"""

        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value=xml_response)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        dominion_client.session.get = Mock(return_value=mock_response)

        start_date = datetime(2025, 2, 1)
        end_date = datetime(2025, 2, 2)

        usage_reads = await dominion_client.async_get_usage_reads(
            account="ELECTRIC",
            start_date=start_date,
            end_date=end_date,
        )

        assert len(usage_reads) == 2
        assert isinstance(usage_reads[0], UsageRead)
        assert usage_reads[0].consumption == 500
        assert usage_reads[1].consumption == 600

        call_args = dominion_client.session.get.call_args
        url = call_args[0][0]
        assert "user_123" in url
        assert "measurement-type=ELECTRIC" in url
        assert "file-type=XML" in url

    @pytest.mark.asyncio
    async def test_async_get_usage_reads_skip_non_interval(self, dominion_client):
        """Test that non-interval consumption entries are skipped."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        xml_response = """<?xml version="1.0" encoding="UTF-8"?>
<feed>
    <entry>
        <title>Some Other Data</title>
        <content>
            <data>Not interval consumption</data>
        </content>
    </entry>
    <entry>
        <title>Interval Consumption Data</title>
        <content>
            <espi:IntervalBlock>
                <espi:interval>
                    <espi:start>1706745600</espi:start>
                </espi:interval>
                <espi:IntervalReading>
                    <espi:timePeriod>
                        <espi:start>1706745600</espi:start>
                        <espi:duration>900</espi:duration>
                    </espi:timePeriod>
                    <espi:value>500</espi:value>
                </espi:IntervalReading>
                <espi:IntervalReading>
                    <espi:timePeriod>
                        <espi:start>1706746500</espi:start>
                        <espi:duration>900</espi:duration>
                    </espi:timePeriod>
                    <espi:value>600</espi:value>
                </espi:IntervalReading>
            </espi:IntervalBlock>
        </content>
    </entry>
</feed>"""

        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value=xml_response)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        dominion_client.session.get = Mock(return_value=mock_response)

        start_date = datetime(2025, 2, 1)
        end_date = datetime(2025, 2, 2)

        usage_reads = await dominion_client.async_get_usage_reads(
            account="ELECTRIC",
            start_date=start_date,
            end_date=end_date,
        )

        assert len(usage_reads) == 2

    @pytest.mark.asyncio
    async def test_async_get_usage_reads_xml_parse_error(self, dominion_client):
        """Test usage reads with XML parsing error."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        xml_response = "This is not valid XML"

        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value=xml_response)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        dominion_client.session.get = Mock(return_value=mock_response)

        start_date = datetime(2025, 2, 1)
        end_date = datetime(2025, 2, 2)

        with pytest.raises(ApiException, match="Unable to parse XML"):
            await dominion_client.async_get_usage_reads(
                account="ELECTRIC",
                start_date=start_date,
                end_date=end_date,
            )

    @pytest.mark.asyncio
    async def test_async_get_usage_reads_client_error(self, dominion_client):
        """Test usage reads with client error."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        dominion_client.session.get = Mock(side_effect=ClientError("Network error"))

        start_date = datetime(2025, 2, 1)
        end_date = datetime(2025, 2, 2)

        with pytest.raises(CannotConnect, match="Failed to connect to API"):
            await dominion_client.async_get_usage_reads(
                account="ELECTRIC",
                start_date=start_date,
                end_date=end_date,
            )

    def test_get_headers_with_token(self, dominion_client):
        """Test getting headers with access token."""
        dominion_client.access_token = "test_token_123"

        headers = dominion_client._get_headers()

        assert headers["User-Agent"] == USER_AGENT
        assert headers["IsAjax"] == "true"
        assert headers["X-Requested-With"] == "XMLHttpRequest"
        assert headers["Host"] == "desc-prodapi.bidgely.com"
        assert headers["Origin"] == "https://account.dominionenergysc.com"
        assert headers["Referer"] == "https://account.dominionenergysc.com/"
        assert headers["X-Bidgely-Client-Type"] == "WIDGETS"
        assert headers["X-Bidgely-Pilot-Id"] == "10106"
        assert headers["Authorization"] == "Bearer test_token_123"

    def test_get_headers_without_token(self, dominion_client):
        """Test getting headers without access token."""
        dominion_client.access_token = None

        headers = dominion_client._get_headers()

        assert "Authorization" not in headers
        assert headers["User-Agent"] == USER_AGENT

    @pytest.mark.asyncio
    async def test_async_get_request_success(self, dominion_client):
        """Test successful GET request."""
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="test response")
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        dominion_client.session.get = Mock(return_value=mock_response)

        result = await dominion_client._async_get_request(
            "https://test.com/api",
            {"User-Agent": "test"},
        )

        assert result == "test response"

    @pytest.mark.asyncio
    async def test_async_get_request_client_error(self, dominion_client):
        """Test GET request with client error."""
        dominion_client.session.get = Mock(side_effect=ClientError("Error"))

        with pytest.raises(CannotConnect) as exc_info:
            await dominion_client._async_get_request(
                "https://test.com/api",
                {"User-Agent": "test"},
            )

        assert "Failed to connect to API" in str(exc_info.value)
        assert exc_info.value.url == "https://test.com/api"

    @pytest.mark.asyncio
    async def test_cannot_connect_exception_attributes(self, dominion_client):
        """Test CannotConnect exception has proper attributes."""
        error = ClientError("Network error")
        error.status = 500
        dominion_client.session.get = Mock(side_effect=error)

        with pytest.raises(CannotConnect) as exc_info:
            await dominion_client._async_get_request(
                "https://test.com/api",
                {"User-Agent": "test"},
            )

        exc = exc_info.value
        assert exc.url == "https://test.com/api"
        assert exc.status == 500
        assert hasattr(exc, "response_text")

    @pytest.mark.asyncio
    async def test_api_exception_attributes(self, dominion_client):
        """Test ApiException exception has proper attributes."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        invalid_xml = "This is not XML"

        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value=invalid_xml)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)

        dominion_client.session.get = Mock(return_value=mock_response)

        start_date = datetime(2025, 2, 1)
        end_date = datetime(2025, 2, 2)

        with pytest.raises(ApiException) as exc_info:
            await dominion_client.async_get_usage_reads(
                account="ELECTRIC",
                start_date=start_date,
                end_date=end_date,
            )

        exc = exc_info.value
        assert exc.url is not None
        assert "user_123" in exc.url
        assert exc.response_text == invalid_xml
        assert hasattr(exc, "status")

    def test_find_verification_token_success(self, dominion_client):
        """Test finding verification token."""
        webpage = '<input name="__RequestVerificationToken" type="hidden" value="abc123" />'

        token = dominion_client._find_verification_token(webpage, "/test", "test_func")

        assert token == "abc123"

    def test_find_verification_token_with_extra_closing(self, dominion_client):
        """Test finding verification token with extra closing tag."""
        webpage = '<input name="__RequestVerificationToken" type="hidden" value="abc123" /><div>other</div>" />'

        token = dominion_client._find_verification_token(webpage, "/test", "test_func")

        assert token == "abc123"

    def test_find_verification_token_not_found(self, dominion_client):
        """Test verification token not found."""
        webpage = "<html><body>No token here</body></html>"

        with pytest.raises(CannotConnect, match="Cannot retrieve request verification token"):
            dominion_client._find_verification_token(webpage, "/test", "test_func")
