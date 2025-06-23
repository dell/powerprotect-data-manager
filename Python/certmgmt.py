#!/usr/bin/env python3

import argparse
import json
import requests
import urllib3

# This script simplifies certificate management in PowerProtect DAta Manager
# Author - Idan Kentor <idan.kentor@dell.com>
# Copyright [2025] [Idan Kentor]

# Script to simplify certificate management in PowerProtect Data Manager
# Examples:
# python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list
# python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a accept -id MTAuMjQ3LjUuNDU6MzAwOTpo4n8G
# python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a accept -host api.idan.openshift-example.com

urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script to simplify certificate management in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'accept'],
                        help='Choose to list certificates or accept a specific one')
    parser.add_argument('-id', '--id', required=False, action='store', default=None,
                        help='Optionally provide the ID the certificate to accept')
    parser.add_argument('-cert-host', '--certhost', required=False, action='store', default=None,
                        help='Optionally provide the certificate host to accept')
    args = parser.parse_args()
    return args


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""
    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " f"{token}",
        }
    payload = json.dumps(payload)
    verify = False
    timeout = 90
    try:
        if verb.lower() == "get":
            response = requests.get(
                uri,
                headers=headers,
                params=params,
                verify=verify,
                timeout=timeout
            )
        else:
            response = requests.request(
                verb,
                uri,
                headers=headers,
                params=params,
                data=payload,
                verify=verify,
                timeout=timeout,
            )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as error:
        print(f"-> Error Connecting to {uri}: {error}")
        raise SystemExit(1) from error
    except requests.exceptions.Timeout as error:
        print(f"-> Connection timed out {urllib3}: {error}")
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if response.status_code in (401, 502):
            return False
        print(
            f"-> The call {response.request.method} {response.url} \
                failed with exception:{error}"
        )
    if not response.content:
        return True
    if uri.endswith("/login"):
        return response.json()["access_token"]
    try:
        return response.json()
    except (AttributeError, ValueError):
        return response.content


def authenticate(uri, user, password):
    """Logins into PowerProtect Data Manager"""
    uri = f"{uri}/login"
    payload = {"username": user, "password": password}
    token = init_rest_call("POST", uri, payload, payload)
    return token


def get_certs(uri, token, cert_id=None, cert_host=None):
    """Retrieves a list of credentials"""
    uri = f"{uri}/certificates"
    query_params = None
    if cert_id:
        uri = f"{uri}/{cert_id}"
    if cert_host:
        query = f'host eq "{cert_host}"'
        query_params = {'filter': query}
    response = init_rest_call("GET", uri, token, None, query_params)
    return response


def accept_cert(uri, token, certs):
    """Performs removal of credentials by ID"""
    uri = f"{uri}/certificates/{certs["id"]}"
    response = init_rest_call("PUT", uri, token, payload=certs)
    return response


def main():
    port = "8443"
    apiendpoint = "/api/v2"
    args = get_args()
    ppdm, user, password = args.server, args.user, args.password
    action, cert_id, cert_host = args.action, args.id, args.certhost
    uri = f"https://{ppdm}:{port}{apiendpoint}"
    token = authenticate(uri, user, password)
    if action == "list":
        certs = get_certs(uri, token)
        print(json.dumps(certs, indent=4))
    elif action == "accept":
        certs = None
        if not cert_host and not cert_id:
            print("Specify either certificate host or ID. Exiting...")
            raise SystemExit(1)
        if cert_host:
            if not cert_id:
                certs = get_certs(uri, token, None, cert_host)
                if not certs:
                    print(f"Could not obtain certificate ID by host {cert_host}. Exiting...")
                    raise SystemExit(1)
                if "content" in certs:
                    if len(certs["content"]) > 1:
                        print(f"Certificate host {cert_host} yielded in more than 1 result. Exiting...")
                        raise SystemExit(1)
                    if len(certs["content"]) == 0:
                        print(f"Certificate host {cert_host} Could not be found. Exiting...")
                        raise SystemExit(1)
                    certs = certs["content"][0]
                cert_id = certs["id"]
        if cert_id:
            if not certs:
                certs = get_certs(uri, token, cert_id)
        certs["state"] = "ACCEPTED"
        result = accept_cert(uri, token, certs)
        if result:
            print(f"Certificate ID {certs["id"]} of host {certs["host"]} accepted successfully")
        else:
            print(f"Certificate ID {certs["id"]} of host {certs["host"]} could not be accepted")


if __name__ == "__main__":
    main()
