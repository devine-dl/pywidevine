import logging
from datetime import datetime

import click

from pywidevine import __version__


@click.group(invoke_without_command=True)
@click.option("-v", "--version", is_flag=True, default=False, help="Print version information.")
@click.option("-d", "--debug", is_flag=True, default=False, help="Enable DEBUG level logs.")
def main(version: bool, debug: bool) -> None:
    """pywidevine—Python Widevine CDM implementation."""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)
    log = logging.getLogger()

    copyright_years = 2022
    current_year = datetime.now().year
    if copyright_years != current_year:
        copyright_years = f"{copyright_years}-{current_year}"

    log.info(f"pywidevine version {__version__} Copyright (c) {copyright_years} rlaphoenix")
    log.info("https://github.com/rlaphoenix/pywidevine")
    if version:
        return
