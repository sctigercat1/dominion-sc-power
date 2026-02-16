"""Tests for utility.py module."""

import json
from datetime import date
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
import pytest

from dominionsc.const import USER_AGENT
from dominionsc.exceptions import ApiException, CannotConnect, InvalidAuth, MfaChallenge
from dominionsc.utility import DominionSCTFAHandler, DominionSCURLHandler, DominionSCUtility


class TestDominionSCURLHandler:
    """Tests for DominionSCURLHandler class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock session."""
        return Mock(spec=aiohttp.ClientSession)

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


class TestDominionSCUtility:
    """Tests for DominionSCUtility class."""

    @pytest.fixture
    def utility(self):
        """Create a utility instance."""
        return DominionSCUtility()

    def test_initialization(self, utility):
        """Test utility initialization."""
        assert utility._tfa_secret is None
        assert utility._name == "Dominion Energy SC"
        assert utility._dominion_endpoint == "https://account.dominionenergysc.com"
        assert utility.bidgely_endpoint == "https://desc-prodapi.bidgely.com"
        assert utility.timezone == "America/New_York"

    def test_find_verification_token_success(self, utility):
        """Test finding verification token."""
        webpage = '<input name="__RequestVerificationToken" type="hidden" value="abc123" />'

        token = utility._find_verification_token(webpage, "/test", "test_func")

        assert token == "abc123"

    def test_find_verification_token_with_extra_closing(self, utility):
        """Test finding verification token with extra closing tag."""
        webpage = '<input name="__RequestVerificationToken" type="hidden" value="abc123" /><div>other</div>" />'

        token = utility._find_verification_token(webpage, "/test", "test_func")

        assert token == "abc123"

    def test_find_verification_token_not_found(self, utility):
        """Test verification token not found."""
        webpage = "<html><body>No token here</body></html>"

        with pytest.raises(CannotConnect, match="Cannot retrieve request verification token"):
            utility._find_verification_token(webpage, "/test", "test_func")

    @pytest.mark.asyncio
    async def test_async_login_success(self, utility):
        """Test successful login flow."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        # Mock responses for each step
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
            access_token, user_id, accounts = await utility.async_login(
                mock_session,
                "test_user",
                "test_pass",
                {"tfa_token": "valid_tfa_token"},
            )

        assert access_token == "access123"
        assert user_id == "user456"
        assert "ELECTRIC" in accounts[0]

    @pytest.mark.asyncio
    async def test_async_login_invalid_credentials(self, utility):
        """Test login with invalid credentials."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "failed"}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="Invalid credentials"):
                await utility.async_login(mock_session, "bad_user", "bad_pass")

    @pytest.mark.asyncio
    async def test_async_login_unexpected_status(self, utility):
        """Test login with unexpected status (not 'failed' or 'twoFA')."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "locked"}}',  # Unexpected status
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="Unsuccessful authentication"):
                await utility.async_login(mock_session, "test_user", "test_pass")

    @pytest.mark.asyncio
    async def test_async_login_invalid_tfa_token(self, utility):
        """Test login with invalid TFA token."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": false}',  # Invalid TFA token
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(MfaChallenge, match="Need new TFA token"):
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "invalid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_no_tfa_token(self, utility):
        """Test login without TFA token raises MfaChallenge."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(MfaChallenge) as exc_info:
                await utility.async_login(mock_session, "test_user", "test_pass")

            assert isinstance(exc_info.value.handler, DominionSCTFAHandler)

    @pytest.mark.asyncio
    async def test_async_login_multiple_accounts_error(self, utility):
        """Test login with multiple accounts raises error."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": false}}',  # Multiple accounts
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(InvalidAuth, match="multiple accounts"):
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_json_decode_error(self, utility):
        """Test login with JSON decode error raises ApiException."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            "This is not valid JSON",  # Will cause JSON decode error
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode Authenticate"):
                await utility.async_login(mock_session, "test_user", "test_pass")

    @pytest.mark.asyncio
    async def test_async_login_init_account_error(self, utility):
        """Test login with account init error."""
        mock_session = Mock(spec=aiohttp.ClientSession)

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
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_bidgely_init_error(self, utility):
        """Test login with bidgely init error."""
        mock_session = Mock(spec=aiohttp.ClientSession)

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
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_bearer_token_error(self, utility):
        """Test login with bearer token retrieval error."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {"payload": "encrypted_token"}}',
            '{"payload": {}}',  # Missing token details
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to get accessToken or userId"):
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_login_with_gas_and_electric(self, utility):
        """Test login returns both gas and electric accounts."""
        mock_session = Mock(spec=aiohttp.ClientSession)

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
            access_token, user_id, accounts = await utility.async_login(
                mock_session,
                "test_user",
                "test_pass",
                {"tfa_token": "valid_token"},
            )

        assert "ELECTRIC" in accounts[0]
        assert "GAS" in accounts[0]

    @pytest.mark.asyncio
    async def test_async_login_measurement_type_error(self, utility):
        """Test login with error decoding measurement types."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {"status": "twoFA"}}',
            '{"data": true}',
            '<input name="__RequestVerificationToken" type="hidden" value="token2" />',
            '{"data": {"singleAccount": true}}',
            '{"data": {"account": {"serviceAddressAndAccountNo": "ACC123"}}}',
            '{"data": {"payload": "encrypted_token"}}',
            '{"payload": {"tokenDetails": {"accessToken": "access123"}, "userProfileDetails": {"userId": "user456"}}}',  # Missing userTypeDetails
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Unable to decode measurement type"):
                await utility.async_login(
                    mock_session,
                    "test_user",
                    "test_pass",
                    {"tfa_token": "valid_token"},
                )

    @pytest.mark.asyncio
    async def test_async_get_forecast_success(self, utility):
        """Test successful forecast retrieval."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            json.dumps(
                {
                    "data": {
                        "amiUsageAlert": {
                            "currentBillUsageStartDate": "2025-02-01T00:00:00",
                            "currentBillUsageEndDate": "2025-02-28T00:00:00",
                            "currentBillThroughDate": "2025-02-15T00:00:00",
                            "totalCostUnbilledConsumption": 125.50,
                            "currentCostPerDay": 9.5,
                            "numberOfDaysInCurrentBill": 28,
                            "lastYearAmountExists": True,
                            "lastYearTotalAmount": 240.00,
                        }
                    }
                }
            ),
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            result = await utility.async_get_forecast(mock_session)

        assert result["start_date"] == date(2025, 2, 1)
        assert result["end_date"] == date(2025, 2, 28)
        assert result["current_date"] == date(2025, 2, 15)
        assert result["cost_to_date"] == 125.50
        assert result["forecasted_cost"] == 266.0  # 9.5 * 28
        assert result["typical_cost"] == 240.00

    @pytest.mark.asyncio
    async def test_async_get_forecast_no_last_year(self, utility):
        """Test forecast without last year data."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            json.dumps(
                {
                    "data": {
                        "amiUsageAlert": {
                            "currentBillUsageStartDate": "2025-02-01T00:00:00",
                            "currentBillUsageEndDate": "2025-02-28T00:00:00",
                            "currentBillThroughDate": "2025-02-15T00:00:00",
                            "totalCostUnbilledConsumption": 125.50,
                            "currentCostPerDay": 10.0,
                            "numberOfDaysInCurrentBill": 28,
                            "lastYearAmountExists": False,
                        }
                    }
                }
            ),
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            result = await utility.async_get_forecast(mock_session)

        assert result["typical_cost"] is None

    @pytest.mark.asyncio
    async def test_async_get_forecast_error(self, utility):
        """Test forecast retrieval with error."""
        mock_session = Mock(spec=aiohttp.ClientSession)

        responses = [
            '<input name="__RequestVerificationToken" type="hidden" value="token1" />',
            '{"data": {}}',  # Missing amiUsageAlert
        ]

        with patch.object(DominionSCURLHandler, "call_api", new=AsyncMock(side_effect=responses)):
            with pytest.raises(ApiException, match="Failed to decode forecast data"):
                await utility.async_get_forecast(mock_session)


class TestDominionSCTFAHandler:
    """Tests for DominionSCTFAHandler class."""

    @pytest.fixture
    def mock_session(self):
        """Create a mock session."""
        return Mock(spec=aiohttp.ClientSession)

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
        # Check that the data includes the PIN code
        json_data = call_args[0][3]  # Fourth positional argument
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
