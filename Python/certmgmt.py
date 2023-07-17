#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json

# Script to simplify certificate management in PowerProtect Data Manager
# Examples:
# python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list
# python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a accept -id MTAuMjQ3LjUuNDU6MzAwOTpo4n8G

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
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
    parser.add_argument('-id', '--id', required='accept' in sys.argv, action='store', default=None,
                        help='Optionally provide the ID the certificate to accept')
    args = parser.parse_args()
    return args

def authenticate(ppdm, user, password, uri):
    # Login
    suffixurl = "/login"
    uri += suffixurl
    headers = {'Content-Type': 'application/json'}
    payload = '{"username": "%s", "password": "%s"}' % (user, password)
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.ConnectionError as err:
        print('Error Connecting to {}: {}'.format(ppdm, err))
        sys.exit(1)
    except requests.exceptions.Timeout as err:
        print('Connection timed out {}: {}'.format(ppdm, err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        sys.exit(1)
    if (response.status_code != 200):
        raise Exception('Login failed for user: {}, code: {}, body: {}'.format(
            user, response.status_code, response.text))
    print('Login for user: {} to PPDM: {}'.format(user, ppdm))
    token = response.json()['access_token']
    return token

def get_certs(uri, token, id=None):
    # Retrieves a list of credentials
    suffixurl = "/certificates"
    if id:
        suffixurl = "/certificates/{}".format(id)
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    return response.json()

def accept_cert(uri, token, certs):
    # Performs removal of credentials by ID
    suffixurl = "/certificates/{}".format(certs["id"])
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.post(uri, headers=headers, data=certs, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202, 204]:
        print('Failed to accept certificate with ID {}, code: {}, body: {}'.format(
				id, response.status_code, response.text))
        return False
    return True

def logout(ppdm, user, uri, token):
    # Logs out of PowerProtect
    suffixurl = "/logout"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.post(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
            print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 204):
        raise Exception('Logout failed for user: {}, code: {}, body: {}'.format(
            user, response.status_code, response.text))
    print('Logout for user: {} from PPDM: {}'.format(user, ppdm))

def main():
    port = "8443"
    apiendpoint = "/api/v2"
    args = get_args()
    ppdm, user, password, action, id = args.server, args.user, args.password, args.action, args.id
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    token = authenticate(ppdm, user, password, uri)
    if (action == 'list'):
        certs = get_certs(uri, token)
        print(json.dumps(certs,indent=4))
    elif (action == 'accept'):
            print("Accepting certificate with ID: {}".format(id))
            certs = get_certs(uri, token, id)
            certs["state"] = "ACCEPTED"
            result = accept_cert(uri, token, certs)
            if result:
                print("Certificate ID {} of host {} accepted successfully".format(certs["id"], certs["host"]))
            else:
                print("Certificate ID {} could not be accepted".format(certs["id"]))
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
