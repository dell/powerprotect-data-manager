#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json

# The purpose of this script is to simplify Inventory / Asset Source removal in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to perform Asset/Inventory source removal in PowerProtect')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'remove'],
                        help='Choose to list all inventory sources or to remove specific one')
    parser.add_argument('-n', '--name', required=False, action='store', default=None,
                        help='Name of the inventory source to list or remove')
    parser.add_argument('-id', '--id', required=False, action='store', default=None,
                        help='Optionally provide the ID of the inventory source to remove')
    parser.add_argument('-t', '--type', required=False, action='store',
                        default=None, help='Optionally provide the ID of the inventory source to remove')
    parser.add_argument('-nop', "--noprompt", required=False, default=False, action='store_true',
                        help='No confirmation prompts would be shown if specified')
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

def get_inv_src(uri, token, name, id, type):
    # Retrieves a list of inventory  sources
    suffixurl = "/inventory-sources"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'not type lk "DEFAULT%"'
    if (type is not None):
        if (type.lower() in ['k8s', 'k8']):
            type = 'KUBERNETES'
        elif (type.lower() == 'dd'):
            type = 'DATADOMAIN'
        filter += 'and type lk "%{}%"'.format(type)
    if (name is not None):
        filter += ' and name lk "%{}%"'.format(name)
    if (id is not None):
        filter += 'and id lk "%{}%"'.format(id)
    params = {'filter': filter}
    try:
        response = requests.get(uri, headers=headers, params=params, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    return response.json()['content']

def remove_inv_src(uri, token, id):
    # Performs removal of inventory source by ID
    suffixurl = "/inventory-sources/{}".format(id)
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.delete(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202, 204]:
        print('Failed to remove asset source with ID {}, code: {}, body: {}'.format(
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
    ppdm, user, password, action = args.server, args.user, args.password, args.action
    name, id, type, prompt = args.name, args.id, args.type, args.noprompt
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    if (all(elem is None for elem in [name, type, id]) and action == 'remove'):
        print ("Please specify either inventory source name, id or type")
        sys.exit(5)
    token = authenticate(ppdm, user, password, uri)
    invsrc = get_inv_src(uri, token, name, id, type)
    if len(invsrc) == 0:
        print('Inventory Source could not be found')
        next
    if (action == 'list'):
        for asset in invsrc:
            print("---------------------------------------------------------")
            print("Inventory Source ID:", asset["id"])
            print("Inventory Source Name:", asset["name"])
            print("Inventory Source Type:", asset["type"])
            print("Inventory Source Version:", asset["version"])
            print("Status After Last Discovery:", asset["lastDiscoveryResult"]["status"])
            print()
    elif (action == 'remove'):
        if (len(invsrc) > 1):
            print ("Inventory Source name: {} yielded in more than 1 result".format(name))
            print("Narrow down the results using the --action list paramater")
        elif (len(invsrc) == 1):
            if (not prompt):
                print("Are you sure you would like to remove inventory source: {} ?(y/n)".format(invsrc[0]["name"]))
                reply = str(input().lower().rstrip())
                if (reply[:1] not in ['y', 'yes']):
                    print("Inventory Source: {} will not be removed".format(invsrc[0]["name"]))
                    logout(ppdm, user, uri, token)
                    sys.exit(10)
            if invsrc[0]["type"] == "KUBERNETES":
                print("Removing K8s Inventory Source is not currently supported")
                logout(ppdm, user, uri, token)
                sys.exit(5)
            print("Removing Inventory Source with name: {} and of type {}".format(invsrc[0]["name"], invsrc[0]["type"]))
            result = remove_inv_src(uri, token, invsrc[0]["id"])
            if result:
                print("Inventory Source: {} removed successfully".format(invsrc[0]["name"]))
            else:
                print("Inventory Source: {} could not be removed".format(invsrc[0]["name"]))
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
