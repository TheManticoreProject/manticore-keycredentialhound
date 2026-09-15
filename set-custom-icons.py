#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : set-custom-icons.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 19 Sep 2025

import argparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def update_icon(base_url, bearer, kind_name, icon_name, icon_color, icon_type="font-awesome", verify=False, debug=False):
    api_v2_custom_nodes_route = "api/v2/custom-nodes"

    r = requests.get(
        url=f"{base_url}/{api_v2_custom_nodes_route}/{kind_name}",
        headers={
            "Authorization": f"Bearer {bearer}",
            "Content-Type": "application/json"
        },
        verify=verify
    )

    if r.status_code == 404:
        print(f"[>] Custom icon for {kind_name} does not exist (HTTP {r.status_code}), creating it...")
        r = requests.post(
            url=f"{base_url}/{api_v2_custom_nodes_route}",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json"
            },
            json={
                "custom_types": {
                    kind_name: {
                        "icon": {
                            "type": icon_type,
                            "name": icon_name,
                            "color": icon_color
                        }
                    }
                }
            },
            verify=verify
        )

        if r.status_code in (200, 201):
            print(f"  └──[+] Custom icon for {kind_name} created successfully")
        else:
            print(f"  └──[!] Failed to create custom icon for {kind_name} (HTTP {r.status_code})")
            print(r.text)
            return

    elif r.status_code == 200:
        print(f"[>] Custom icon for {kind_name} already exists (HTTP {r.status_code}), updating it...")
        r = requests.put(
            url=f"{base_url}/{api_v2_custom_nodes_route}/{kind_name}",
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json"
            },
            json={
                "config": {
                    "icon": {
                        "type": icon_type,
                        "name": icon_name,
                        "color": icon_color
                    }
                }
            },
            verify=verify
        )

        if r.status_code == 200:
            print(f"  └──[+] Custom icon for {kind_name} updated successfully")
        else:
            print(f"  └──[!] Failed to update custom icon for {kind_name} (HTTP {r.status_code})")
            print(r.text)
            return
    else:
        print(f"[!] Failed to get status of custom icon for {kind_name} (HTTP {r.status_code})")
        print(r.text)
        return


def parse_args():
    parser = argparse.ArgumentParser(description="Set custom icons for nodes")

    parser.add_argument("--debug", action="store_true", help="Debug mode")

    # BloodHound configuration
    bloodhound_group = parser.add_argument_group('BloodHound Configuration')
    bloodhound_group.add_argument("-H", "--host", type=str, default="127.0.0.1", help="BloodHound host")
    bloodhound_group.add_argument("-P", "--port", type=int, default=8080, help="BloodHound port")
    bloodhound_group.add_argument("-b", "--bearer", type=str, required=True, help="Bearer token for authentication")
    bloodhound_group.add_argument("-s", "--use-https", action="store_true", help="Use HTTPS instead of HTTP to reach BloodHound")
    bloodhound_group.add_argument("-k", "--no-verify", action="store_true", help="Do not verify the TLS certificate of the BloodHound host")

    return parser.parse_args()


# One entry per primary kind emitted by the collector. Keep in sync with kinds.go.
#
# Each algorithm gets its own glyph, and each visibility its own color: key
# material in msDS-KeyCredentialLink is a public key blob, so a private key node
# is a finding on its own and has to stand out at a glance.
KINDS = [
    ("KC_KeyCredential", "vault", "#8e44ad"),
    ("KC_Device", "laptop", "#2980b9"),

    ("KC_UnknownKeyMaterial", "question", "#7f8c8d"),

    ("KC_RSAPublicKey", "key", "#16a085"),
    ("KC_DSAPublicKey", "signature", "#16a085"),
    ("KC_ECCPublicKey", "bezier-curve", "#16a085"),

    ("KC_RSAPrivateKey", "key", "#c0392b"),
    ("KC_DSAPrivateKey", "signature", "#c0392b"),
    ("KC_ECCPrivateKey", "bezier-curve", "#c0392b"),
]

LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")

if __name__ == "__main__":
    args = parse_args()

    scheme = "https" if args.use_https else "http"
    url = f"{scheme}://{args.host}:{args.port}"

    if not args.use_https and args.host not in LOOPBACK_HOSTS:
        print(f"[!] Sending the bearer token in cleartext to {args.host}, use --use-https to protect it.")

    for kind, icon_name, icon_color in KINDS:
        update_icon(base_url=url, bearer=args.bearer, kind_name=kind, icon_name=icon_name, icon_color=icon_color, verify=(not args.no_verify), debug=args.debug)
