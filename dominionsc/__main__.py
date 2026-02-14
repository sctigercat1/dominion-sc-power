"""Demo usage of dominion-sc-power library."""

import argparse
import asyncio
import csv
import json
import logging
from datetime import datetime, timedelta
from getpass import getpass

import aiohttp

from dominionsc import DominionSC, DominionSCUtility, InvalidAuth, MfaChallenge, create_cookie_jar


async def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--username",
        help="Username for logging into the utility's website. If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--password",
        help="Password for logging into the utility's website. If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--login_data_file",
        help="Where to store login data from MFA. If not provided, login data will not be saved.",
    )
    parser.add_argument(
        "--start_date",
        help="Start datetime for historical data. Defaults to 7 days ago",
        type=lambda s: datetime.fromisoformat(s),
        default=datetime.now() - timedelta(days=7),
    )
    parser.add_argument(
        "--end_date",
        help="end datetime for historical data. Defaults to now",
        type=lambda s: datetime.fromisoformat(s),
        default=datetime.now(),
    )
    parser.add_argument(
        "--csv",
        help="csv file to store data",
    )
    parser.add_argument("-v", "--verbose", help="enable verbose logging", action="count", default=0)
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG - args.verbose + 1 if args.verbose > 0 else logging.INFO)

    utility = DominionSCUtility()
    username = args.username or input("Username: ")
    password = args.password or getpass("Password: ")
    login_data = None
    if args.login_data_file:
        try:
            with open(args.login_data_file) as file:
                login_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        dominionsc = DominionSC(session, utility, username, password, login_data)
        try:
            await dominionsc.async_login()
        except MfaChallenge as e:
            handler = e.handler
            print(f"TFA Challenge: {e}")
            options = await handler.async_get_tfa_options()
            if options:
                print("Please select an TFA option:")
                for i, (_, value) in enumerate(options.items()):
                    print(f"  [{i + 1}] {value}")
                choice_index = int(input("Enter the number for your choice: ")) - 1
                choice_key = list(options.keys())[choice_index]
                await handler.async_select_tfa_option(choice_key)
                print(f"A security code has been sent via {options[choice_key]}.")
            code = input("Enter the security code: ")
            try:
                login_data = await handler.async_submit_tfa_code(code)
            except InvalidAuth:
                logging.exception("TFA failed")
                return
            else:
                print("TFA validation successful.")
                if args.login_data_file:
                    with open(args.login_data_file, "w") as file:
                        json.dump(login_data, file, indent=4)
                dominionsc.login_data = login_data
                await dominionsc.async_login()
        except InvalidAuth:
            logging.exception("Login failed")
            return

        if not args.csv:
            forecast = await dominionsc.async_get_forecast()
            print("\nCurrent bill forecast:", forecast)

        accounts = await dominionsc.async_get_accounts()
        for account in accounts[0]:
            usage_data = await dominionsc.async_get_usage_reads(
                account,
                args.start_date,
                args.end_date,
            )

            if args.csv:
                with open(args.csv, "w", newline="") as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(["start_time", "end_time", "consumption"])
                    for usage_read in usage_data:
                        writer.writerow(
                            [
                                usage_read.start_time,
                                usage_read.end_time,
                                usage_read.consumption,
                            ]
                        )
            else:
                print("start_time\tend_time\tconsumption")
                for usage_read in usage_data:
                    print(f"{usage_read.start_time}\t{usage_read.end_time}\t{usage_read.consumption}")
                print()


if __name__ == "__main__":
    asyncio.run(_main())
