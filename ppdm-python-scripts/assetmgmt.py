#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json
import time

# The purpose of this script is to facilitate asset management in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to manage Assets in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-n', '--name', required=False, action='store',
                        help='Optionally provide the name of the inventory source to discover')
    parser.add_argument('-t', '--type', required=False, action='store', default='vCenter',
                        help='Optionally provide the type of inventory source to discover')
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

def get_inventory_src(ppdm, uri, token, name, invtype):
    # Get Inventory Source
    suffixurl = "/inventory-sources"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    if invtype:
        if invtype.lower() in ["vcenter", "vc"]:
            filter = 'type eq "VCENTER"'
        elif invtype.lower() in ["k8s", "kubernetes"]:
            filter = 'type eq "KUBERNETES"'
        elif invtype.lower() in ["dd", "datadomain", "data domain"]:
            filter = 'type eq "EXTERNALDATADOMAIN"'
        elif invtype.lower() == ["app", "appgroup"]:
            filter = 'type eq "DEFAULTAPPGROUP"'
    if name:
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

def discover_inventory_src(ppdm, uri, token, invsrc):
    # Discovers an Inventory Source
    suffixurl = "/discoveries"
    uri += suffixurl
    invsrcuri = "/inventory-sources/"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    if invsrc["type"] == "EXTERNALDATADOMAIN":
        level = "ProtectableData"
    else:
        level = "DataCopies"
    payload = json.dumps({
        'start' : '/{}/{}'.format(invsrcuri, invsrc["id"]),
		'level' : level
		})
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202]:
        raise Exception('Failed to run discovery {} {} on level {}, code: {}, body: {}'.format(
				invsrc["type"], invsrc["id"], level, response.status_code, response.text))
    if 'activityId' in response.json():
        return response.json()['activityId']
    if 'taskId' in response.json():
        return response.json()['taskId']
    if 'jobId' in response.json():
        return response.json()['jobId']
    return None

def monitor_activity(ppdm, uri, token, activityid):
    # Monitors an activity by its ID
    timeout = 300 # 5 minutes timeout
    interval = 10 # 10 seconds interval
    suffixurl = "/activities/"
    uri += suffixurl + activityid
    start = time.time()
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    while True:
        if (time.time() - start) > timeout:
            break
        try:
            response = requests.get(uri, headers=headers, verify=False)
            response.raise_for_status()
        except requests.exceptions.RequestException as err:
            print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
        if (response.status_code != 200):
            raise Exception('Failed to query {}, code: {}, body: {}'.format(
                uri, response.status_code, response.text))
        print('Activity {} {}'.format(activityid, response.json()['state']))
        if response.json()['state'] == 'COMPLETED':
            return response.json()['result']['status']
        time.sleep(interval)
    return 'TIMEOUT'

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
    ppdm, user, password, name, invtype = args.server, args.user, args.password, args.name, args.type
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    token = authenticate(ppdm, user, password, uri)
    invsrclist = get_inventory_src(ppdm, uri, token, name, invtype)
    if len(invsrclist) == 0:
        raise Exception('No asset was found with the provided criteria')
    for invsrc in invsrclist:
        print('Found Inventory Source {} of type {}'.format(invsrc['name'], invsrc['type']))
        activityid = discover_inventory_src(ppdm, uri, token, invsrc)
        print('Discovery has been triggered for {}'.format(invsrc['name']))
        result = monitor_activity(ppdm, uri, token, activityid)
        print('Discovery activity {} status {}'.format(activityid, result))
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
