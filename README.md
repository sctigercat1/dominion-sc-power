# dominion-sc-power

A Python library for accessing historical and forecasted energy usage and cost data from Dominion Energy South Carolina's API.

This library is used by the custom [Home Assistant Integration for Dominion Energy SC](https://github.com/sctigercat1/ha-dominion-sc).

## Features

- Retrieve historical energy usage data (electric and gas)
- Get current bill forecasts with cost projections
- Support for two-factor authentication (TFA)
- Async/await architecture using aiohttp
- Support for multiple energy sources (electric and gas)

## Limitations

- Only one service address per Dominion account is currently supported (mainly because I do not know what the API responses look like for users with multiple service addresses) - you will get an error if this applies to you - please report the error under issues which should include the relevant API response
- TFA is required (again mainly because I do not know what the flow without TFA looks like) - report this error under issues if it applies to you
- No explicit support for solar (grid export)
- Data is delayed by 24-48 hours as this is when it is reported by Dominion
- Some of the current implementation is a little clunky - will probably be refactored in a future update

## Installation

- Not yet available on PyPi (will be eventually) - for now see development environment instructions below.

```bash
pip install dominion-sc-power
```

## Development

### Setup Development Environment

```bash
# Clone and setup
git clone https://github.com/sctigercat1/dominion-sc-power.git
cd dominion-sc-power
./scripts/setup
```

### Code Validation

After each change, please run the following scripts to format/check your code with `ruff` and run unit tests.

```bash
./scripts/lint
./scripts/test
```

### Contributing

Contributions are welcome! Please submit a pull request with your proposed changes.

## Command Line Interface

The library includes a CLI for quick data retrieval:

```bash
# Basic usage (will prompt for credentials)
python -m dominionsc

# With credentials
python -m dominionsc --username your_username --password your_password

# Get historical data and save to CSV
python -m dominionsc --start_date 2025-02-01 --end_date 2025-02-08 --csv output.csv

# Store TFA token for reuse
python -m dominionsc --login_data_file login.json

# Verbose logging
python -m dominionsc -vv
```

### CLI Arguments

- `--username`: Username for the utility website
- `--password`: Password for the utility website
- `--login_data_file`: JSON file to store/load TFA tokens
- `--start_date`: Start date for historical data (ISO format, default: 7 days ago)
- `--end_date`: End date for historical data (ISO format, default: now)
- `--csv`: Output CSV file path for usage data
- `-v, --verbose`: Enable verbose logging (use multiple times for more verbosity)

## Sample Implementation

```python
import asyncio
import aiohttp
from dominionsc import DominionSC, DominionSCUtility, create_cookie_jar
from datetime import datetime, timedelta

async def main():
    utility = DominionSCUtility()
    username = "your_username"
    password = "your_password"
    
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        client = DominionSC(session, utility, username, password)
        
        # Login
        await client.async_login()
        
        # ** Handle TFA (see below) **
        
        # Get forecast
        forecast = await client.async_get_forecast()
        print(f"Forecasted cost: ${forecast.forecasted_cost}")
        
        # Get usage data
        accounts = await client.async_get_accounts()
        for account in accounts[0]:
            # accounts[1] is the service address
            # each account is in ['ELECTRIC' or 'GAS']
            usage = await client.async_get_usage_reads(
                account,
                start_date=datetime.now() - timedelta(days=7),
                end_date=datetime.now()
            )
            for reading in usage:
                print(f"{reading.start_time}: {reading.consumption} Wh")

asyncio.run(main())
```

## Handling two-Factor Authentication (TFA)

If your account has TFA enabled (see limitations above), you'll need to handle the `MfaChallenge` exception:

```python
from dominionsc import MfaChallenge, InvalidAuth

try:
    await client.async_login()
except MfaChallenge as e:
    handler = e.handler
    
    # Get available TFA options
    options = await handler.async_get_tfa_options()
    print("Available TFA methods:", options)
    
    # Select an option (e.g., SMS or email)
    option_id = list(options.keys())[0]
    await handler.async_select_tfa_option(option_id)
    
    # Get code from user
    code = input("Enter the security code: ")
    
    # Submit code and get login data for future use
    login_data = await handler.async_submit_tfa_code(code)
    
    # Save login_data to skip TFA next time
    # Pass it as: DominionSC(session, utility, username, password, login_data)
    
    # Retry login
    client.login_data = login_data
    await client.async_login()
```

## Credits

This project was inspired by [Opower](https://github.com/tronikos/opower). Much appreciated!

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This is an unofficial integration and is not affiliated with, endorsed by, or connected to Dominion Energy SC. Use at your own risk. The authors are not responsible for any issues that may arise from using this integration.
