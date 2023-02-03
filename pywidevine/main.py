import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from zlib import crc32

import click
import requests
from construct import ConstructError
from unidecode import unidecode, UnidecodeError
import yaml
from google.protobuf.json_format import MessageToDict

from pywidevine import __version__
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.license_protocol_pb2 import LicenseType, FileHashes
from pywidevine.pssh import PSSH


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

    log.info("pywidevine version %s Copyright (c) %s rlaphoenix", __version__, copyright_years)
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
@click.option("-p", "--privacy", is_flag=True, default=False,
              help="Use Privacy Mode, off by default.")
def license_(device: Path, pssh: str, server: str, type_: str, privacy: bool):
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

    # prepare pssh
    pssh = PSSH(pssh)

    # load device
    device = Device.load(device)
    log.info("[+] Loaded Device (%s L%s)", device.system_id, device.security_level)
    log.debug(device)

    # load cdm
    cdm = Cdm.from_device(device)
    log.info("[+] Loaded CDM")
    log.debug(cdm)

    # open cdm session
    session_id = cdm.open()
    log.info("[+] Opened CDM Session: %s", session_id.hex())

    if privacy:
        # get service cert for license server via cert challenge
        service_cert = requests.post(
            url=server,
            data=cdm.service_certificate_challenge
        )
        if service_cert.status_code != 200:
            log.error(
                "[-] Failed to get Service Privacy Certificate: [%s] %s",
                service_cert.status_code,
                service_cert.text
            )
            return
        service_cert = service_cert.content
        provider_id = cdm.set_service_certificate(session_id, service_cert)
        log.info("[+] Set Service Privacy Certificate: %s", provider_id)
        log.debug(service_cert)

    # get license challenge
    license_type = LicenseType.Value(type_)
    challenge = cdm.get_license_challenge(session_id, pssh, license_type, privacy_mode=True)
    log.info("[+] Created License Request Message (Challenge)")
    log.debug(challenge)

    # send license challenge
    licence = requests.post(
        url=server,
        data=challenge
    )
    if licence.status_code != 200:
        log.error("[-] Failed to send challenge: [%s] %s", licence.status_code, licence.text)
        return
    licence = licence.content
    log.info("[+] Got License Message")
    log.debug(licence)

    # parse license challenge
    cdm.parse_license(session_id, licence)
    log.info("[+] License Parsed Successfully")

    # print keys
    for key in cdm.get_keys(session_id):
        log.info("[%s] %s:%s", key.type, key.kid.hex, key.key.hex())

    # close session, disposes of session data
    cdm.close(session_id)


@main.command()
@click.argument("device", type=Path)
@click.option("-p", "--privacy", is_flag=True, default=False,
              help="Use Privacy Mode, off by default.")
@click.pass_context
def test(ctx: click.Context, device: Path, privacy: bool):
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

    # this runs the `cdm license` CLI-command code with the data we set above
    # it will print information as it goes to the terminal
    ctx.invoke(
        license_,
        device=device,
        pssh=pssh,
        server=license_server,
        type_=LicenseType.Name(license_type),
        privacy=privacy
    )


@main.command()
@click.option("-t", "--type", "type_", type=click.Choice([x.name for x in Device.Types], case_sensitive=False),
              required=True, help="Device Type")
@click.option("-l", "--level", type=click.IntRange(1, 3), required=True, help="Device Security Level")
@click.option("-k", "--key", type=Path, required=True, help="Device RSA Private Key in PEM or DER format")
@click.option("-c", "--client_id", type=Path, required=True, help="Widevine ClientIdentification Blob file")
@click.option("-v", "--vmp", type=Path, default=None, help="Widevine FileHashes Blob file")
@click.option("-o", "--output", type=Path, default=None, help="Output Directory")
@click.pass_context
def create_device(
    ctx: click.Context,
    type_: str,
    level: int,
    key: Path,
    client_id: Path,
    vmp: Optional[Path] = None,
    output: Optional[Path] = None
) -> None:
    """
    Create a Widevine Device (.wvd) file from an RSA Private Key (PEM or DER) and Client ID Blob.
    Optionally also a VMP (Verified Media Path) Blob, which will be stored in the Client ID.
    """
    if not key.is_file():
        raise click.UsageError("key: Not a path to a file, or it doesn't exist.", ctx)
    if not client_id.is_file():
        raise click.UsageError("client_id: Not a path to a file, or it doesn't exist.", ctx)
    if vmp and not vmp.is_file():
        raise click.UsageError("vmp: Not a path to a file, or it doesn't exist.", ctx)

    log = logging.getLogger("create-device")

    device = Device(
        type_=Device.Types[type_.upper()],
        security_level=level,
        flags=None,
        private_key=key.read_bytes(),
        client_id=client_id.read_bytes()
    )

    if vmp:
        new_vmp_data = vmp.read_bytes()
        if device.client_id.vmp_data and device.client_id.vmp_data != new_vmp_data:
            log.warning("Client ID already has Verified Media Path data")
        device.client_id.vmp_data = new_vmp_data

    client_info = {}
    for entry in device.client_id.client_info:
        client_info[entry.name] = entry.value

    wvd_bin = device.dumps()

    name = f"{client_info['company_name']} {client_info['model_name']}"
    if client_info.get("widevine_cdm_version"):
        name += f" {client_info['widevine_cdm_version']}"
    name += f" {crc32(wvd_bin).to_bytes(4, 'big').hex()}"

    try:
        name = unidecode(name.strip().lower().replace(" ", "_"))
    except UnidecodeError as e:
        raise click.ClickException(f"Failed to sanitize name, {e}")

    out_path = (output or Path.cwd()) / f"{name}_{device.system_id}_l{device.security_level}.wvd"
    out_path.write_bytes(wvd_bin)

    log.info("Created Widevine Device (.wvd) file, %s", out_path.name)
    log.info(" + Type: %s", device.type.name)
    log.info(" + System ID: %s", device.system_id)
    log.info(" + Security Level: %s", device.security_level)
    log.info(" + Flags: %s", device.flags)
    log.info(" + Private Key: %s (%s bit)", bool(device.private_key), device.private_key.size_in_bits())
    log.info(" + Client ID: %s (%s bytes)", bool(device.client_id), len(device.client_id.SerializeToString()))
    if device.client_id.vmp_data:
        file_hashes_ = FileHashes()
        file_hashes_.ParseFromString(device.client_id.vmp_data)
        log.info(" + VMP: True (%s signatures)", len(file_hashes_.signatures))
    else:
        log.info(" + VMP: False")
    log.info(" + Saved to: %s", out_path.absolute())


@main.command()
@click.argument("wvd_path", type=Path)
@click.option("-o", "--out_dir", type=Path, default=None, help="Output Directory")
@click.pass_context
def export_device(ctx: click.Context, wvd_path: Path, out_dir: Optional[Path] = None) -> None:
    """
    Export a Widevine Device (.wvd) file to an RSA Private Key (PEM and DER) and Client ID Blob.
    Optionally also a VMP (Verified Media Path) Blob, which will be stored in the Client ID.

    If an output directory is not specified, it will be stored in the current working directory.
    """
    if not wvd_path.is_file():
        raise click.UsageError("wvd_path: Not a path to a file, or it doesn't exist.", ctx)

    log = logging.getLogger("export-device")
    log.info("Exporting Widevine Device (.wvd) file, %s", wvd_path.stem)

    if not out_dir:
        out_dir = Path.cwd()

    out_path = out_dir / wvd_path.stem
    if out_path.exists():
        if any(out_path.iterdir()):
            log.error("Output directory is not empty, cannot overwrite.")
            return
        else:
            log.warning("Output directory already exists, but is empty.")
    else:
        out_path.mkdir(parents=True)

    device = Device.load(wvd_path)

    log.info(f"L{device.security_level} {device.system_id} {device.type.name}")
    log.info(f"Saving to: {out_path}")

    device_meta = {
        "wvd": {
            "device_type": device.type.name,
            "security_level": device.security_level,
            **device.flags
        },
        "client_info": {},
        "capabilities": MessageToDict(device.client_id, preserving_proto_field_name=True)["client_capabilities"]
    }
    for client_info in device.client_id.client_info:
        device_meta["client_info"][client_info.name] = client_info.value

    device_meta_path = out_path / "metadata.yml"
    device_meta_path.write_text(yaml.dump(device_meta), encoding="utf8")
    log.info("Exported Device Metadata as metadata.yml")

    if device.private_key:
        private_key_path = out_path / "private_key.pem"
        private_key_path.write_text(
            data=device.private_key.export_key().decode(),
            encoding="utf8"
        )
        private_key_path.with_suffix(".der").write_bytes(
            device.private_key.export_key(format="DER")
        )
        log.info("Exported Private Key as private_key.der and private_key.pem")
    else:
        log.warning("No Private Key available")

    if device.client_id:
        client_id_path = out_path / "client_id.bin"
        client_id_path.write_bytes(device.client_id.SerializeToString())
        log.info("Exported Client ID as client_id.bin")
    else:
        log.warning("No Client ID available")

    if device.client_id.vmp_data:
        vmp_path = out_path / "vmp.bin"
        vmp_path.write_bytes(device.client_id.vmp_data)
        log.info("Exported VMP (File Hashes) as vmp.bin")
    else:
        log.info("No VMP (File Hashes) available")


@main.command()
@click.argument("path", type=Path)
@click.pass_context
def migrate(ctx: click.Context, path: Path) -> None:
    """
    Upgrade from earlier versions of the Widevine Device (.wvd) format.

    The path argument can be a direct path to a Widevine Device (.wvd) file, or a path
    to a folder of Widevine Devices files.

    The migrated devices are saved to its original location, overwriting the old version.
    """
    if not path.exists():
        raise click.UsageError(f"path: The path '{path}' does not exist.", ctx)

    log = logging.getLogger("migrate")

    if path.is_dir():
        devices = list(path.glob("*.wvd"))
    else:
        devices = [path]

    migrated = 0
    for device in devices:
        log.info("Migrating %s...", device.name)

        try:
            new_device = Device.migrate(device.read_bytes())
        except (ConstructError, ValueError) as e:
            log.error(" - %s", e)
            continue

        log.debug(new_device)
        new_device.dump(device)

        log.info(" + Success")
        migrated += 1

    log.info("Migrated %s/%s devices!", migrated, len(devices))


@main.command("serve", short_help="Serve your local CDM and Widevine Devices Remotely.")
@click.argument("config", type=Path)
@click.option("-h", "--host", type=str, default="127.0.0.1", help="Host to serve from.")
@click.option("-p", "--port", type=int, default=8786, help="Port to serve from.")
def serve_(config: Path, host: str, port: int):
    """
    Serve your local CDM and Widevine Devices Remotely.

    \b
    [CONFIG] is a path to a serve config file.
    See `serve.example.yml` for an example config file.

    \b
    Host as 127.0.0.1 may block remote access even if port-forwarded.
    Instead, use 0.0.0.0 and ensure the TCP port you choose is forwarded.
    """
    from pywidevine import serve
    import yaml

    config = yaml.safe_load(config.read_text(encoding="utf8"))
    serve.run(config, host, port)
