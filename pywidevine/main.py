import logging
from datetime import datetime
from pathlib import Path

import click
import requests

from pywidevine import __version__
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.license_protocol_pb2 import LicenseType


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


@main.command(name="license")
@click.argument("device", type=Path)
@click.argument("pssh", type=str)
@click.argument("server", type=str)
@click.option("-t", "--type", "type_", type=click.Choice(LicenseType.keys(), case_sensitive=False),
              default="STREAMING",
              help="License Type to Request.")
@click.option("-r", "--raw", is_flag=True, default=False,
              help="PSSH is Raw.")
@click.option("-p", "--privacy", is_flag=True, default=False,
              help="Use Privacy Mode, off by default.")
def license_(device: Path, pssh: str, server: str, type_: str, raw: bool, privacy: bool):
    """
    Make a License Request for PSSH to SERVER using DEVICE.
    It will return a list of all keys within the returned license.

    This expects the Licence Server to be a simple opaque interface where the Challenge
    is sent as is (as bytes), and the License response is returned as is (as bytes).
    This is a common behavior for some License Servers and is our only option for a generic
    licensing function.

    You may modify this function to change how it sends the Challenge and how it parses
    the License response. However, for non-generic license calls, I recommend creating a
    new script that imports and uses the pywidevine module instead. This generic function
    is only useful as a quick generic license call.

    This is also a great way of showing you how to use pywidevine in your own projects.
    """
    log = logging.getLogger("license")

    # load device
    device = Device.load(device)
    log.info(f"[+] Loaded Device ({device.system_id} L{device.security_level})")
    log.debug(device)

    # load cdm
    cdm = Cdm(device, pssh, raw)
    log.info(f"[+] Loaded CDM with PSSH: {pssh}")
    log.debug(cdm)

    if privacy:
        # get service cert for license server via cert challenge
        service_cert = requests.post(
            url=server,
            data=cdm.service_certificate_challenge
        )
        if service_cert.status_code != 200:
            log.error(f"[-] Failed to get Service Privacy Certificate: [{service_cert.status_code}] {service_cert.text}")
            return
        service_cert = service_cert.content
        cdm.set_service_certificate(service_cert)
        log.info("[+] Set Service Privacy Certificate")
        log.debug(service_cert)

    # get license challenge
    license_type = LicenseType.Value(type_)
    challenge = cdm.get_license_challenge(license_type, privacy_mode=True)
    log.info("[+] Created License Request Message (Challenge)")
    log.debug(challenge)

    # send license challenge
    licence = requests.post(
        url=server,
        data=challenge
    )
    if licence.status_code != 200:
        log.error(f"[-] Failed to send challenge: [{licence.status_code}] {licence.text}")
        return
    licence = licence.content
    log.info("[+] Got License Message")
    log.debug(licence)

    # parse license challenge
    keys = cdm.parse_license(licence)
    log.info("[+] License Parsed Successfully")

    # print keys
    for key in keys:
        log.info(f"[{key.type}] {key.kid.hex}:{key.key.hex()}")


@main.command()
@click.argument("device", type=Path)
@click.pass_context
def test(ctx: click.Context, device: Path):
    """
    Test the CDM code by getting Content Keys for Bitmovin's Art of Motion example.
    https://bitmovin.com/demos/drm
    https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/mpds/11331.mpd

    The device argument is a Path to a Widevine Device (.wvd) file which contains
    the device private key among other required information.
    """
    # The PSSH is the same for all tracks both video and audio.
    # However, this might not be the case for all services/manifests.
    pssh = "AAAAW3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAADsIARIQ62dqu8s0Xpa" \
           "7z2FmMPGj2hoNd2lkZXZpbmVfdGVzdCIQZmtqM2xqYVNkZmFsa3IzaioCSEQyAA=="

    # This License Server requires no authorization at all, no cookies, no credentials
    # nothing. This is often not the case for real services.
    license_server = "https://cwip-shaka-proxy.appspot.com/no_auth"

    # Specify OFFLINE if it's a PSSH for a download/offline mode title, e.g., the
    # Download feature on Netflix Apps. Otherwise, use STREAMING or AUTOMATIC.
    license_type = LicenseType.STREAMING

    # If the PSSH is not a valid mp4 pssh box, nor a valid CENC Header (init data) then
    # set this to True, otherwise leave it False.
    raw = False

    # this runs the `cdm license` CLI-command code with the data we set above
    # it will print information as it goes to the terminal
    ctx.invoke(
        license_,
        device=device,
        pssh=pssh,
        server=license_server,
        type_=LicenseType.Name(license_type),
        raw=raw
    )
