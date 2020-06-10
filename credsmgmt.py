#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json

# The purpose of this script is to simplify K8s Credential Management in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to simplify K8s credentials management in PowerProtect')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['add', 'remove'],
                        help='Choose to add credentials or remove one of them')
    parser.add_argument('-n', '--name', required=False, action='store', default=None,
                        help='Name of the credentials to add or remove')
    parser.add_argument('-id', '--id', required='add' in sys.argv, action='store', default=None,
                        help='Optionally provide the ID the credentials to add or remove')
    parser.add_argument('-token', '--token', required='add' in sys.argv, action='store', default=None,
                        help='Provide the token of the credentials to add')
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
    authtoken = response.json()['access_token']
    return authtoken

def add_creds(uri, authtoken, name, token):
    # Adds credentials
    suffixurl = "/credentials"
    uri += suffixurl
    type = "KUBERNETES"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(authtoken)}
    payload = json.dumps({
        "name" : name,
        "username" : "null",
        "password" : token,
        "type" : type,
        "method" : "TOKEN",
        "internal" : "false"
		})
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202, 204]:
        print('Failed to remove credentials with ID {}, code: {}, body: {}'.format(
				id, response.status_code, response.text))
        return False
    return True

def get_creds(uri, authtoken, name, id):
    # Retrieves a list of credentials
    suffixurl = "/credentials"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(authtoken)}
    filter = 'internal eq false'
    if id != None:
        filter += ' and id lk "%{}%"'.format(id)
    if name != None:
        filter += ' and name lk "%{}%"'.format(name)
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

def remove_creds(uri, authtoken, id):
    # Performs removal of credentials by ID
    suffixurl = "/credentials/{}".format(id)
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(authtoken)}
    try:
        response = requests.delete(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202, 204]:
        print('Failed to remove credentials with ID {}, code: {}, body: {}'.format(
				id, response.status_code, response.text))
        return False
    return True

def logout(ppdm, user, uri, authtoken):
    # Logs out of PowerProtect
    suffixurl = "/logout"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(authtoken)}
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
    name, token, prompt, id = args.name, args.token, args.noprompt, args.id
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    authtoken = authenticate(ppdm, user, password, uri)
    if (action == 'add'):
        result = add_creds(uri, authtoken, name, token)
        if result:
            print("Credentials: {} added successfully".format(name))
    elif (action == 'remove'):
        credlist = get_creds(uri, authtoken, name, id)
        if (len(credlist) == 0):
            print ("Could not match credentials name: {}".format(name))
        elif (len(credlist) > 1):
            print ("Credentials name: {} yielded in more than 1 result".format(name))
            print("Narrow down the results using the exact name")
            for index in range(len(credlist)):
                print ("Credentials Name: {} with ID: {}".format(credlist[index]["name"], credlist[index]["id"]))
        elif (len(credlist) == 1):
            if (not prompt):
                print("Are you sure you would like to remove credentials: {} ?(y/n)".format(credlist[0]["name"]))
                reply = str(input().lower().rstrip())
                if (reply[:1] not in ['y', 'yes']):
                    print("Credentials: {} will not be removed".format(credlist[0]["name"]))
                    logout(ppdm, user, uri, authtoken)
                    sys.exit(10)
            print("Removing credentials with Name: {} and of ID: {}".format(credlist[0]["name"], credlist[0]["id"]))
            result = remove_creds(uri, authtoken, credlist[0]["id"])
            if result:
                print("Credentials: {} removed successfully".format(credlist[0]["name"]))
            else:
                print("Credentials: {} could not be removed".format(credlist[0]["name"]))
    logout(ppdm, user, uri, authtoken)

if __name__ == "__main__":
    main()
