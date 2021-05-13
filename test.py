from __future__ import print_function, absolute_import, unicode_literals
import fido2
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client
from getpass import getpass
from binascii import b2a_hex
import sys
import os

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


# Locate a device
for dev in enumerate_devices():
    client = Fido2Client(dev, "https://example.com")
    if "hmac-secret" in client.info.extensions:
        break
else:
    print("No Authenticator with the HmacSecret extension found!")
    sys.exit(1)

use_nfc = CtapPcscDevice and isinstance(dev, CtapPcscDevice)

# Prepare parameters for makeCredential
rp = {"id": "example.com", "name": "Example RP"}
user = {"id": b"user_id", "name": "A. User"}
challenge = b"Y2hhbGxlbmdl"

# Prompt for PIN if needed
pin = None
if client.info.options.get("clientPin"):
    pin = getpass("Please enter PIN:")
else:
    print("no pin")

# Create a credential with a HmacSecret
if not use_nfc:
    print("\nTouch your authenticator device now...\n")
result = client.make_credential(
    {
        "rp": rp,
        "user": user,
        "challenge": challenge,
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "extensions": {"hmacCreateSecret": True},
    },
    pin=pin,
)

# HmacSecret result:
if not result.extension_results.get("hmacCreateSecret"):
    print("Failed to create credential with HmacSecret")
    sys.exit(1)

credential = result.attestation_object.auth_data.credential_data
print("New credential created, with the HmacSecret extension.")

# Prepare parameters for getAssertion
challenge = b"Q0hBTExFTkdF"  # Use a new challenge for each call.
allow_list = [{"type": "public-key", "id": credential.credential_id}]

# Generate a salt for HmacSecret:
salt = os.urandom(32)
print("Authenticate with salt:", b2a_hex(salt))

# Authenticate the credential
if not use_nfc:
    print("\nTouch your authenticator device now...\n")

result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt}},
    },
    pin=pin,
).get_response(
    0
)  # Only one cred in allowList, only one response.

output1 = result.extension_results["hmacGetSecret"]["output1"]
print("Authenticated, secret:", b2a_hex(output1))

# Authenticate again, using two salts to generate two secrets:

# Generate a second salt for HmacSecret:
salt2 = os.urandom(32)
print("Authenticate with second salt:", b2a_hex(salt2))

if not use_nfc:
    print("\nTouch your authenticator device now...\n")

# The first salt is reused, which should result in the same secret.
result = client.get_assertion(
    {
        "rpId": rp["id"],
        "challenge": challenge,
        "allowCredentials": allow_list,
        "extensions": {"hmacGetSecret": {"salt1": salt, "salt2": salt2}},
    },
    pin=pin,
).get_response(
    0
)  # One cred in allowCredentials, single response.

output = result.extension_results["hmacGetSecret"]
print("Old secret:", b2a_hex(output["output1"]))
print("New secret:", b2a_hex(output["output2"]))
