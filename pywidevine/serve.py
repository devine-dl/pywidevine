import base64
import sys
from pathlib import Path
from typing import Optional, Union

try:
    from aiohttp import web
except ImportError:
    print(
        "Missing the extra dependencies for serve functionality. "
        "You may install them under poetry with `poetry install -E serve`, "
        "or under pip with `pip install pywidevine[serve]`."
    )
    sys.exit(1)

from pywidevine import __version__
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.exceptions import TooManySessions, InvalidSession
from pywidevine.license_protocol_pb2 import LicenseType, License

routes = web.RouteTableDef()


async def _startup(app: web.Application):
    app["cdms"]: dict[tuple[str, str], Cdm] = {}
    app["config"]["devices"] = {
        path.stem: path
        for x in app["config"]["devices"]
        for path in [Path(x)]
    }
    for device in app["config"]["devices"].values():
        if not device.is_file():
            raise FileNotFoundError(f"Device file does not exist: {device}")


async def _cleanup(app: web.Application):
    app["cdms"].clear()
    del app["cdms"]
    app["config"].clear()
    del app["config"]


@routes.get("/")
async def ping(_) -> web.Response:
    return web.json_response({
        "status": 200,
        "message": "Pong!"
    })


@routes.get("/{device}/open")
async def open(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]
    user = request.app["config"]["users"][secret_key]

    if device_name not in user["devices"] or device_name not in request.app["config"]["devices"]:
        # we don't want to be verbose with the error as to not reveal device names
        # by trial and error to users that are not authorized to use them
        return web.json_response({
            "status": 403,
            "message": f"Device '{device_name}' is not found or you are not authorized to use it."
        }, status=403)

    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        device = Device.load(request.app["config"]["devices"][device_name])
        cdm = request.app["cdms"][(secret_key, device_name)] = Cdm.from_device(device)

    try:
        session_id = cdm.open()
    except TooManySessions as e:
        return web.json_response({
            "status": 400,
            "message": str(e)
        }, status=400)

    return web.json_response({
        "status": 200,
        "message": "Success",
        "data": {
            "session_id": session_id.hex(),
            "device": {
                "system_id": cdm.system_id,
                "security_level": cdm.security_level
            }
        }
    })


@routes.get("/{device}/close/{session_id}")
async def close(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]
    session_id = bytes.fromhex(request.match_info["session_id"])

    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        return web.json_response({
            "status": 400,
            "message": f"No Cdm session for {device_name} has been opened yet. No session to close."
        }, status=400)

    try:
        cdm.close(session_id)
    except InvalidSession as e:
        return web.json_response({
            "status": 400,
            "message": str(e)
        }, status=400)

    return web.json_response({
        "status": 200,
        "message": f"Successfully closed Session '{session_id.hex()}'."
    })


@routes.post("/{device}/set_service_certificate")
async def set_service_certificate(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id", "certificate"):
        if required_field == "certificate":
            has_field = required_field in body  # it needs the key, but can be empty/null
        else:
            has_field = body.get(required_field)
        if not has_field:
            return web.json_response({
                "status": 400,
                "message": f"Missing required field '{required_field}' in JSON body."
            }, status=400)

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get cdm
    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        return web.json_response({
            "status": 400,
            "message": f"No Cdm session for {device_name} has been opened yet. No session to use."
        }, status=400)

    if session_id not in cdm._sessions:
        # This can happen if:
        # - API server gets shutdown/restarted,
        # - The user calls /challenge before /open,
        # - The user called /open on a different IP Address
        # - The user closed the session
        return web.json_response({
            "status": 400,
            "message": "Invalid Session ID. Session ID may have Expired."
        }, status=400)

    # set service certificate
    certificate = body.get("certificate")
    provider_id = cdm.set_service_certificate(session_id, certificate)

    return web.json_response({
        "status": 200,
        "message": f"Successfully {['set', 'unset'][not certificate]} the Service Certificate.",
        "data": {
            "provider_id": provider_id
        }
    })


@routes.post("/{device}/challenge/{license_type}")
async def challenge(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id", "init_data"):
        if not body.get(required_field):
            return web.json_response({
                "status": 400,
                "message": f"Missing required field '{required_field}' in JSON body."
            }, status=400)

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get cdm
    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        return web.json_response({
            "status": 400,
            "message": f"No Cdm session for {device_name} has been opened yet. No session to use."
        }, status=400)

    if session_id not in cdm._sessions:
        # This can happen if:
        # - API server gets shutdown/restarted,
        # - The user calls /challenge before /open,
        # - The user called /open on a different IP Address
        # - The user closed the session
        return web.json_response({
            "status": 400,
            "message": "Invalid Session ID. Session ID may have Expired."
        }, status=400)

    # enforce service certificate (opt-in)
    if request.app["config"]["force_privacy_mode"] and not cdm._sessions[session_id].service_certificate:
        return web.json_response({
            "status": 403,
            "message": "No Service Certificate set but Privacy Mode is Enforced."
        }, status=403)

    # get challenge
    license_request = cdm.get_license_challenge(
        session_id=session_id,
        init_data=body["init_data"],
        type_=LicenseType.Value(request.match_info["license_type"]),
        privacy_mode=True
    )

    return web.json_response({
        "status": 200,
        "message": "Success",
        "data": {
            "challenge_b64": base64.b64encode(license_request).decode()
        }
    }, status=200)


@routes.post("/{device}/keys/{key_type}")
async def keys(request: web.Request) -> web.Response:
    secret_key = request.headers["X-Secret-Key"]
    device_name = request.match_info["device"]

    body = await request.json()
    for required_field in ("session_id", "license_message"):
        if not body.get(required_field):
            return web.json_response({
                "status": 400,
                "message": f"Missing required field '{required_field}' in JSON body."
            }, status=400)

    # get session id
    session_id = bytes.fromhex(body["session_id"])

    # get key type
    key_type = request.match_info["key_type"]
    if key_type == "ALL":
        key_type = None
    else:
        try:
            if key_type.isdigit():
                key_type = License.KeyContainer.KeyType.Name(int(key_type))
            else:
                License.KeyContainer.KeyType.Value(key_type)  # only test
        except ValueError as e:
            return web.json_response({
                "status": 400,
                "message": f"The Key Type value is invalid, {e}"
            }, status=400)

    # get cdm
    cdm = request.app["cdms"].get((secret_key, device_name))
    if not cdm:
        return web.json_response({
            "status": 400,
            "message": f"No Cdm session for {device_name} has been opened yet. No session to use."
        }, status=400)

    if session_id not in cdm._sessions:
        # This can happen if:
        # - API server gets shutdown/restarted,
        # - The user calls /challenge before /open,
        # - The user called /open on a different IP Address
        # - The user closed the session
        return web.json_response({
            "status": 400,
            "message": "Invalid Session ID. Session ID may have Expired."
        }, status=400)

    # parse the license message
    cdm.parse_license(session_id, body["license_message"])

    # prepare the keys
    license_keys = [
        {
            "key_id": key.kid.hex,
            "key": key.key.hex(),
            "type": key.type,
            "permissions": key.permissions,
        }
        for key in cdm._sessions[session_id].keys
        if not key_type or key.type == key_type
    ]

    return web.json_response({
        "status": 200,
        "message": "Success",
        "data": {
            # TODO: Add derived context keys like enc/mac[client]/mac[server]
            "keys": license_keys
        }
    })


@web.middleware
async def authentication(request: web.Request, handler) -> web.Response:
    response = None
    if request.path != "/":
        secret_key = request.headers.get("X-Secret-Key")
        if not secret_key:
            request.app.logger.debug(f"{request.remote} did not provide authorization.")
            response = web.json_response({
                "status": "401",
                "message": "Secret Key is Empty."
            }, status=401)
        elif secret_key not in request.app["config"]["users"]:
            request.app.logger.debug(f"{request.remote} failed authentication with '{secret_key}'.")
            response = web.json_response({
                "status": "401",
                "message": "Secret Key is Invalid, the Key is case-sensitive."
            }, status=401)

    if response is None:
        try:
            response = await handler(request)
        except web.HTTPException as e:
            request.app.logger.error(f"An unexpected error has occurred, {e}")
            response = web.json_response({
                "status": 500,
                "message": e.reason
            }, status=500)

    response.headers.update({
        "Server": f"https://github.com/rlaphoenix/pywidevine serve v{__version__}"
    })

    return response


def run(config: dict, host: Optional[Union[str, web.HostSequence]] = None, port: Optional[int] = None):
    app = web.Application(middlewares=[authentication])
    app.on_startup.append(_startup)
    app.on_cleanup.append(_cleanup)
    app.add_routes(routes)
    app["config"] = config
    web.run_app(app, host=host, port=port)
