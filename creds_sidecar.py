#!/usr/bin/env python3
"""Local WebRTC-credentials sidecar for the Tuya IPC bridge.

Reuses the working petsseries mobile session (Philips id_token -> Tuya mobile
API, signed by the native thing_security signer service) to serve *fresh*
WebRTC signaling credentials to the Go bridge over localhost. This replaces the
static hardcoded values in ``pkg/tuya/hardcoded_config.go`` and, in
particular, survives ``motoId`` rotation without a rebuild.

The bridge fetches ``GET /webrtc?devId=<id>`` right before (re)opening a
session. The response is the raw ``thing.m.ipc.rtc.config.get`` result (whose
JSON already matches the Go ``WebRTCConfig`` struct) with the device localKey
merged in for the Protocol-2.2 AES layer.

Credential material passes through this service; bind it to localhost only and
never log the payload.

Env:
  PETSERIES_TOKEN_FILE   path to persisted Philips tokens.json (refresh-rotated
                         in place). Seed once from the HA config entry.
  PETSERIES_SIDECAR_ADDR bind address, default 127.0.0.1:8766
  plus the usual PETSERIES_TUYA_SIGNER* signer-service env.
"""
from __future__ import annotations

import logging
import os

from aiohttp import web

from petsseries import PetsSeriesClient
from tuya_mobile import mqtt_client_id, mqtt_credentials

_LOGGER = logging.getLogger("pet_creds_sidecar")

TOKEN_FILE = os.environ.get("PETSERIES_TOKEN_FILE", "/data/philips_tokens.json")


async def _fetch(device_id: str) -> dict:
    """Return fresh WebRTC config, local key, and MQTT session config."""
    client = PetsSeriesClient(token_file=TOKEN_FILE)
    try:
        await client.initialize()           # refreshes + persists rotated tokens
        await client.ensure_token_valid()   # guarantee a live id_token for login
        webrtc = await client.get_cloud_webrtc_config(device_id)
        if not webrtc:
            raise RuntimeError("empty WebRTC config (device offline or auth?)")
        definition = await client.get_cloud_device_definition(device_id)
        local_key = definition.get("localKey")
        if local_key:
            webrtc["localKey"] = local_key
        mobile = client._tuya_mobile
        if mobile is None or not mobile.uid or not mobile.ecode:
            raise RuntimeError("Tuya mobile login returned no MQTT session fields")
        mqtt = mqtt_credentials(
                mobile.signer,
                uid=mobile.uid,
                sid=mobile.sid,
                ecode=mobile.ecode,
                partner_id=os.environ.get("PETSERIES_TUYA_PARTNER_ID", "p2065237"),
            )
        # Protocol 302 signaling is device-addressed.  The shared helper's
        # control-channel topics are account-addressed and use the opposite
        # direction, so they must not leak into the camera bridge.
        mqtt["publish_topic"] = f"smart/mb/out/{device_id}"
        mqtt["subscribe_topic"] = f"smart/mb/in/{device_id}"
        webrtc["mqtt"] = {
            **mqtt,
            "broker": os.environ.get("PETSERIES_TUYA_MQTT_BROKER", "ssl://m1.tuyaeu.com:8883"),
            "client_id": mqtt_client_id("com.versuni.nbx.petsseries"),
            "uid": mobile.uid,
        }
        return webrtc
    finally:
        await client.close()


async def handle_webrtc(request: web.Request) -> web.Response:
    device_id = request.query.get("devId")
    if not device_id:
        return web.json_response({"error": "missing devId"}, status=400)
    try:
        payload = await _fetch(device_id)
    except Exception as exc:  # surface a clean error; never leak a stack to net
        _LOGGER.error("webrtc fetch failed for %s: %s", device_id, exc)
        return web.json_response({"error": str(exc)}, status=502)
    return web.json_response(payload)


async def handle_health(_request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    addr = os.environ.get("PETSERIES_SIDECAR_ADDR", "127.0.0.1:8766")
    host, _, port = addr.partition(":")
    app = web.Application()
    app.add_routes([
        web.get("/webrtc", handle_webrtc),
        web.get("/health", handle_health),
    ])
    web.run_app(app, host=host or "127.0.0.1", port=int(port or "8766"))


if __name__ == "__main__":
    main()
