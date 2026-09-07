import os

import urllib3
from getpass import getpass
import plistlib as plist
import json
import uuid
import pbkdf2
import requests
import hashlib
import hmac
import base64
import locale
import logging
import re
from datetime import datetime, timezone
import srp._pysrp as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Hash import SHA256

from endpoint import mh_config

# Created here so that it is consistent
USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()

# Configure SRP library for compatibility with Apple's implementation
srp.rfc5054_enable()
srp.no_username_in_x()

# Disable SSL Warning
urllib3.disable_warnings()

logger = logging.getLogger()


class AppleAuthError(RuntimeError):
    """Raised when Apple returns a structured authentication failure."""


def _raise_for_apple_status(response, stage):
    status = response.get("Status") or {}
    code = status.get("ec")
    if code not in (None, 0):
        message = status.get("em") or status.get("ed") or "Unknown Apple authentication error"
        raise AppleAuthError(f"{stage} failed: {message} (Apple code {code})")


def _require_fields(response, fields, stage):
    missing = [field for field in fields if field not in response]
    if missing:
        raise AppleAuthError(f"{stage} returned an incomplete response; missing {', '.join(missing)}")


def _second_factor_method(value=None):
    method = (value or os.getenv("MACLESS_2FA_METHOD", "trusted_device")).strip().lower()
    aliases = {"trusted": "trusted_device", "device": "trusted_device"}
    method = aliases.get(method, method)
    if method not in {"trusted_device", "sms", "auto"}:
        raise AppleAuthError(
            "MACLESS_2FA_METHOD must be trusted_device, sms, or auto"
        )
    if method == "auto":
        choice = input("2FA method [trusted_device/sms] (default trusted_device): ").strip().lower()
        method = aliases.get(choice, choice) if choice else "trusted_device"
        if method not in {"trusted_device", "sms"}:
            raise AppleAuthError("Unsupported 2FA method")
    return method


def icloud_login_mobileme(username='', password='', second_factor=None):
    print("")  # Sometimes no output
    if not username:
        username = input('Apple ID: ')
    if not password:
        password = getpass('Password: ')
    username = username.strip()

    session = requests.Session()
    g = gsa_authenticate(
        username,
        password,
        _second_factor_method(second_factor),
        session=session,
    )
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    adsid = g["adsid"]

    data = {
        "apple-id": username,
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": str(USER_ID),
    }
    data = plist.dumps(data)
    headers = {
        "X-Apple-ADSID": adsid,
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>'
    }
    headers.update(generate_anisette_headers())

    logger.info("Registering device after login")
    with session.post(
            "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
            auth=(username, pet),
            data=data,
            headers=headers,
            verify=False,
    ) as resp:
        resp.raise_for_status()
    response = f"HTTP-Code: {resp.status_code}\n{resp.text}"
    logger.debug(response)
    return plist.loads(resp.content)


def gsa_authenticate(
        username,
        password,
        second_factor="trusted_device",
        two_factor_round=0,
        session=None,
):
    session = session or requests.Session()
    # Password is None as we'll provide it later
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, a = usr.start_authentication()
    logger.info("Authentication request initialization")
    r = gsa_authenticated_request(
        {"A2k": a, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"},
        session,
    )

    _raise_for_apple_status(r, "Authentication initialization")
    _require_fields(r, ["sp", "s", "i", "B", "c"], "Authentication initialization")
    if r["sp"] not in ["s2k", "s2k_fo"]:
        raise AppleAuthError(
            f"Unsupported Apple password protocol: {r['sp']}"
        )

    # Change the password out from under the SRP library, as we couldn't calculate it without the salt.
    usr.p = encrypt_password(password, r["s"], r["i"], r["sp"])

    m = usr.process_challenge(r["s"], r["B"])

    # Make sure we processed the challenge correctly
    if m is None:
        raise AppleAuthError("Failed to process Apple's authentication challenge")
    logger.info("Authentication request completion")
    resp = gsa_authenticated_request(
        {"c": r["c"], "M1": m, "u": username, "o": "complete"},
        session,
    )

    _raise_for_apple_status(resp, "Authentication completion")
    # Make sure that the server's session key matches our session key (and thus that they are not an imposter)
    if "M2" not in resp:
        raise AppleAuthError("Authentication completion did not return a server proof")
    usr.verify_session(resp["M2"])
    if not usr.authenticated():
        raise AppleAuthError("Failed to verify Apple's authentication session")

    spd = decrypt_cbc(usr, resp["spd"])
    # For some reason plistlib doesn't accept it without the header...
    PLISTHEADER = b"""\
<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>
"""
    spd = plist.loads(PLISTHEADER + spd)

    status = resp.get("Status") or {}
    if status.get("au") in ["trustedDeviceSecondaryAuth", "secondaryAuth"]:
        if two_factor_round >= 1:
            raise AppleAuthError(
                "Apple requested 2FA again after successful verification; "
                "the Anisette device identity may be inconsistent"
            )
        logger.info("2FA required, using %s", second_factor)
        # Replace bytes with strings
        for k, v in spd.items():
            if isinstance(v, bytes):
                spd[k] = base64.b64encode(v).decode()
        if second_factor == "trusted_device":
            trusted_second_factor(spd["adsid"], spd["GsIdmsToken"], session)
        else:
            sms_second_factor(spd["adsid"], spd["GsIdmsToken"], session)

        return gsa_authenticate(
            username,
            password,
            second_factor,
            two_factor_round + 1,
            session,
        )
    elif "au" in status:
        raise AppleAuthError(f"Unsupported Apple 2FA mode: {status['au']}")
    else:
        return spd


def gsa_authenticated_request(parameters, session=None):
    session = session or requests.Session()
    body = {
        "Header": {"Version": "1.0.1"},
        "Request": {"cpd": generate_cpd()},
    }
    body["Request"].update(parameters)

    headers = {
        "Content-Type": "text/x-xml-plist",
        "Accept": "*/*",
        "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        "X-MMe-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }

    with session.post(
            "https://gsa.apple.com/grandslam/GsService2",
            headers=headers,
            data=plist.dumps(body),
            verify=False,
            timeout=5,
    ) as resp:
        resp.raise_for_status()

    response = f"HTTP-Code: {resp.status_code}\n{resp.text}"
    logger.debug(response)

    return plist.loads(resp.content)["Response"]


def generate_cpd():
    cpd = {
        # Many of these values are not strictly necessary, but may be tracked by Apple
        "bootstrap": True,  # All implementations set this to true
        "icscrec": True,  # Only AltServer sets this to true
        "pbe": False,  # All implementations explicitly set this to false
        "prkgen": True,  # I've also seen ckgen
        "svct": "iCloud",  # In certian circumstances, this can be 'iTunes' or 'iCloud'
    }

    cpd.update(generate_anisette_headers())
    return cpd


def generate_anisette_headers():
    with requests.get(mh_config.getAnisetteServer(), timeout=5) as response:
        response.raise_for_status()
        anisette = response.json()
        required = {"X-Apple-I-MD", "X-Apple-I-MD-M"}
        missing = sorted(required - anisette.keys())
        if missing:
            raise AppleAuthError(
                f"Anisette response is missing required headers: {', '.join(missing)}"
            )

        # Preserve the provisioned identity as one coherent unit. Mixing MD/MD-M
        # from the server with locally generated device IDs makes Apple challenge
        # the client repeatedly even after a valid second factor.
        apple_headers = {
            key: value for key, value in anisette.items()
            if key.lower().startswith(("x-apple-", "x-mme-")) or key.lower() == "loc"
        }
        for key, value in generate_meta_headers(
                user_id=USER_ID, device_id=DEVICE_ID).items():
            apple_headers.setdefault(key, value)
        a = apple_headers
    return a


def generate_meta_headers(serial="0", user_id=uuid.uuid4(), device_id=uuid.uuid4()):
    return {
        "X-Apple-I-Client-Time": datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z",
        "X-Apple-I-TimeZone": str(datetime.now(timezone.utc).astimezone().tzinfo),
        "loc": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-Locale": locale.getdefaultlocale()[0] or "en_US",
        "X-Apple-I-MD-RINFO": "17106176",  # either 17106176 or 50660608
        "X-Apple-I-MD-LU": base64.b64encode(str(user_id).upper().encode()).decode(),
        "X-Mme-Device-Id": str(device_id).upper(),
        "X-Apple-I-SRL-NO": serial,  # Serial number
    }


def encrypt_password(password, salt, iterations, protocol):
    assert protocol in ["s2k", "s2k_fo"]
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return pbkdf2.PBKDF2(p, salt, iterations, SHA256).read(32)


def create_session_key(usr, name):
    k = usr.get_session_key()
    if k is None:
        raise Exception("No session key")
    return hmac.new(k, name.encode(), hashlib.sha256).digest()


def decrypt_cbc(usr, data):
    extra_data_key = create_session_key(usr, "extra data key:")
    extra_data_iv = create_session_key(usr, "extra data iv:")
    # Get only the first 16 bytes of the iv
    extra_data_iv = extra_data_iv[:16]

    # Decrypt with AES CBC
    cipher = Cipher(algorithms.AES(extra_data_key), modes.CBC(extra_data_iv))
    decryptor = cipher.decryptor()
    data = decryptor.update(data) + decryptor.finalize()
    # Remove PKCS#7 padding
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()


def _identity_headers(dsid, idms_token):
    identity_token = base64.b64encode(
        (dsid + ":" + idms_token).encode()).decode()
    headers = {
        "User-Agent": "Xcode",
        "Accept-Language": "en-us",
        "X-Apple-Identity-Token": identity_token,
        "X-Apple-App-Info": "com.apple.gs.xcode.auth",
        "X-Xcode-Version": "11.2 (11B41)",
        "X-Mme-Client-Info": '<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>'
    }
    headers.update(generate_anisette_headers())
    return headers


def trusted_second_factor(dsid, idms_token, session):
    """Use the GSA trusted-device path that matches the SRP login session."""
    headers = _identity_headers(dsid, idms_token)

    with session.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=headers,
            verify=False,
            timeout=10,
    ) as response:
        response.raise_for_status()

    code = getpass("Enter the 6-digit code shown on a trusted Apple device: ").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise AppleAuthError("Trusted-device verification requires a 6-digit code")

    headers["security-code"] = code
    with session.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=headers,
            verify=False,
            timeout=10,
    ) as response:
        response.raise_for_status()

    logger.info("Trusted-device 2FA successful")


def sms_second_factor(dsid, idms_token, session):
    """Accept an Apple-delivered SMS code without mixing GSA and web sessions."""
    headers = _identity_headers(dsid, idms_token)
    pattern = r'<script.*class="boot_args">\s*(.*?)\s*</script>'
    with session.get(
            "https://gsa.apple.com/auth",
            headers=headers,
            verify=False,
            timeout=10,
    ) as auth:
        auth.raise_for_status()
        sms_id = 1
        match = re.search(pattern, auth.text, re.DOTALL)
        if match:
            boot_args = json.loads(match.group(1).strip())
            sms_id = boot_args.get("direct", {}).get(
                "phoneNumberVerification", {}).get(
                    "trustedPhoneNumber", {}).get("id", sms_id)
        logger.info("Using phone with id %s for SMS2FA", sms_id)

    code = input(
        "Enter the 6-digit SMS code already delivered by Apple, "
        "or type 'trusted' to use a trusted device instead: "
    ).strip()
    if code.lower() in {"trusted", "device", "trusted_device"}:
        return trusted_second_factor(dsid, idms_token, session)
    if not re.fullmatch(r"\d{6}", code):
        raise AppleAuthError(
            "No usable SMS code was received. Apple's idmsa resend endpoint "
            "requires a web-auth session and cannot be called with a GSA identity token; "
            "retry with MACLESS_2FA_METHOD=trusted_device."
        )

    body = {
        "phoneNumber": {"id": sms_id},
        "mode": "sms",
        "securityCode": {"code": code},
    }
    with session.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            json=body,
            headers=headers,
            verify=False,
            timeout=5,
    ) as response:
        response.raise_for_status()
        if "X-Apple-DSID" not in response.headers:
            raise AppleAuthError(
                "SMS verification was not accepted by the GSA session"
            )

    logger.info("SMS 2FA successful")
