"""Tests for dominionsc.py module."""

from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, Mock

import aiohttp
import pytest
from aiohttp.client_exceptions import ClientError, ClientResponseError

from dominionsc.const import USER_AGENT
from dominionsc.dominionsc import DominionSC, Forecast, UsageRead
from dominionsc.exceptions import ApiException, CannotConnect, InvalidAuth
from dominionsc.utility import DominionSCUtility


@pytest.fixture
def mock_session():
    """Create a mock aiohttp session."""
    session = Mock(spec=aiohttp.ClientSession)
    return session


@pytest.fixture
def mock_utility():
    """Create a mock utility."""
    utility = Mock(spec=DominionSCUtility)
    utility.timezone = "America/New_York"
    utility.bidgely_endpoint = "https://desc-prodapi.bidgely.com"
    return utility


@pytest.fixture
def dominion_client(mock_session, mock_utility):
    """Create a DominionSC client for testing."""
    return DominionSC(
        session=mock_session,
        utility=mock_utility,
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


class TestDominionSC:
    """Tests for DominionSC class."""

    def test_init_default_login_data(self, mock_session, mock_utility):
        """Test initialization with default login_data."""
        client = DominionSC(
            session=mock_session,
            utility=mock_utility,
            username="user",
            password="pass",
        )

        assert client.session == mock_session
        assert client.utility == mock_utility
        assert client.username == "user"
        assert client.password == "pass"
        assert client.login_data == {}
        assert client.access_token is None
        assert client.user_id is None
        assert client.accounts == []

    def test_init_with_login_data(self, dominion_client):
        """Test initialization with login_data."""
        assert dominion_client.login_data == {"token": "test_token"}

    @pytest.mark.asyncio
    async def test_async_login_success(self, dominion_client, mock_utility):
        """Test successful login."""
        mock_utility.async_login = AsyncMock(return_value=("access_123", "user_456", ["account1", "account2"]))

        await dominion_client.async_login()

        assert dominion_client.access_token == "access_123"
        assert dominion_client.user_id == "user_456"
        assert dominion_client.accounts == ["account1", "account2"]
        mock_utility.async_login.assert_called_once_with(
            dominion_client.session,
            "test_user",
            "test_pass",
            {"token": "test_token"},
        )

    @pytest.mark.asyncio
    async def test_async_login_invalid_auth_401(self, dominion_client, mock_utility):
        """Test login with 401 error raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=401,
            message="Unauthorized",
        )
        mock_utility.async_login = AsyncMock(side_effect=error)

        with pytest.raises(CannotConnect):
            await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_invalid_auth_403(self, dominion_client, mock_utility):
        """Test login with 403 error raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=403,
            message="Forbidden",
        )
        mock_utility.async_login = AsyncMock(side_effect=error)

        with pytest.raises(CannotConnect):
            await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_invalid_auth_499(self, dominion_client, mock_utility):
        """Test login with 499 error raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=499,
            message="Custom error",
        )
        mock_utility.async_login = AsyncMock(side_effect=error)

        with pytest.raises(CannotConnect):
            await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_cannot_connect_other_status(self, dominion_client, mock_utility):
        """Test login with other status code raises CannotConnect."""
        error = ClientResponseError(
            request_info=Mock(),
            history=(),
            status=500,
            message="Server Error",
        )
        mock_utility.async_login = AsyncMock(side_effect=error)

        with pytest.raises(CannotConnect):
            await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_login_client_error(self, dominion_client, mock_utility):
        """Test login with ClientError raises CannotConnect."""
        error = ClientError("Connection failed")
        mock_utility.async_login = AsyncMock(side_effect=error)

        with pytest.raises(CannotConnect):
            await dominion_client.async_login()

    @pytest.mark.asyncio
    async def test_async_get_accounts(self, dominion_client):
        """Test getting accounts."""
        dominion_client.accounts = ["account1", "account2"]

        accounts = await dominion_client.async_get_accounts()

        assert accounts == ["account1", "account2"]

    def test_get_timezone(self, dominion_client, mock_utility):
        """Test getting timezone."""
        mock_utility.timezone = "America/New_York"

        timezone = dominion_client.get_timezone()

        assert timezone == "America/New_York"

    @pytest.mark.asyncio
    async def test_async_get_forecast_success(self, dominion_client, mock_utility):
        """Test successful forecast retrieval."""
        dominion_client.accounts = ["account1"]
        mock_utility.async_get_forecast = AsyncMock(
            return_value={
                "start_date": date(2025, 2, 1),
                "end_date": date(2025, 2, 28),
                "current_date": date(2025, 2, 15),
                "cost_to_date": 100.0,
                "forecasted_cost": 200.0,
                "typical_cost": 195.0,
            }
        )

        forecast = await dominion_client.async_get_forecast()

        assert isinstance(forecast, Forecast)
        assert forecast.start_date == date(2025, 2, 1)
        assert forecast.end_date == date(2025, 2, 28)
        assert forecast.current_date == date(2025, 2, 15)
        assert forecast.cost_to_date == 100.0
        assert forecast.forecasted_cost == 200.0
        assert forecast.typical_cost == 195.0
        mock_utility.async_get_forecast.assert_called_once_with(dominion_client.session)

    @pytest.mark.asyncio
    async def test_async_get_forecast_not_logged_in(self, dominion_client):
        """Test forecast retrieval when not logged in."""
        dominion_client.accounts = []

        with pytest.raises(InvalidAuth, match="User not logged in"):
            await dominion_client.async_get_forecast()

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

        start_date = datetime(2025, 2, 1, 10, 30, 0)
        end_date = datetime(2025, 2, 2, 10, 30, 0)

        usage_reads = await dominion_client.async_get_usage_reads(
            account="ELECTRIC",
            start_date=start_date,
            end_date=end_date,
        )

        assert len(usage_reads) == 2
        assert all(isinstance(read, UsageRead) for read in usage_reads)
        assert usage_reads[0].consumption == 500
        assert usage_reads[1].consumption == 600

        # Verify the URL was constructed correctly
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

        # Should only get the Interval Consumption entry, not the "Some Other Data" entry
        assert len(usage_reads) == 2

    @pytest.mark.asyncio
    async def test_async_get_usage_reads_xml_parse_error(self, dominion_client):
        """Test usage reads with XML parsing error."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        # Invalid XML
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

        # Verify exception attributes
        exc = exc_info.value
        assert exc.url == "https://test.com/api"
        assert exc.status == 500
        # response_text may be None for ClientError
        assert hasattr(exc, "response_text")

    @pytest.mark.asyncio
    async def test_api_exception_attributes(self, dominion_client):
        """Test ApiException exception has proper attributes."""
        dominion_client.user_id = "user_123"
        dominion_client.access_token = "token_abc"

        # Invalid XML that will cause parsing error
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

        # Verify exception attributes
        exc = exc_info.value
        assert exc.url is not None
        assert "user_123" in exc.url
        assert exc.response_text == invalid_xml
        # status may be None for parsing errors
        assert hasattr(exc, "status")
