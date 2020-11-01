#!/usr/bin/env python3

import argparse
import requests
import urllib3
import json
import sys

# Update the schedule of an existing Protection Policy in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to update Protection Policy Schedule in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')

    parser.add_argument('-name', '--assetname', required=True, action='store',
                        help='Provide the name of the protected asset')
    parser.add_argument('-type', '--assettype', required=True, action='store',
                        help='Provide the type of protected asset')

    parser.add_argument('-action', '--action', required=True, choices=['display_schedule', 'update_schedule'],
                        help='Display the existing schedule or update the existing schedule')

    parser.add_argument('-json', '--jsonfile', required=('update_schedule' in sys.argv),
                        help='Provide the json file name with the json body')

    args = parser.parse_args()
    return args

def authenticate(ppdm, user, password, uri):
    # Login
    print('\nRetrieving authorization token')
    loginendpoint = '/login'
    uri += loginendpoint
    headers = {'Content-Type': 'application/json'}
    payload = '{"username": "%s", "password": "%s"}' % (user, password)
    try:
        response = requests.post(
            uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('Login failed for user: {}, code: {}, body: {}'.format(
                user, response.status_code, response.text))
        print('\nUser: {} logged in to PPDM: {}'.format(user, ppdm))
    except requests.exceptions.ConnectionError as errc:
        print('\nError Connecting to {}: {}'.format(ppdm, errc))
        sys.exit()
    except requests.exceptions.Timeout as errt:
        print('\nConnection timed out, make sure that there is connectivity to {}: {}'.format(
            ppdm, errt))
        sys.exit()
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()
    # Parse the response and extract the access_token
    accesstoken = response.json()['access_token']
    return accesstoken

def get_asset_details(uri, accesstoken, assetname, assettype):
    # Get asset using the type and name and parse the protection policy id
    print('\nFetching asset using name: {} and type: {}'.format(
        assetname, assettype))
    assetsendpoint = '/assets'
    assetsapifilter = '?filter=type%20eq%20%22'+assettype + \
        '%22%20and%20name%20lk%20%22%25'+assetname+'%25%22'
    uri += assetsendpoint + assetsapifilter
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nCould not fetch asset details: , code: {}, body: {}'.format(
                response.status_code, response.text))
        if len(response.json()['content']) == 0:
            print('\nNo asset found matching criteria - name: {} and type: {}'.format(
                assetname, assettype))
            sys.exit()
        elif len(response.json()['content']) > 1:
            print(
                '\nMultiple assets found matching criteria. Please refine the search further.')
            sys.exit()
        else:
            assetid = response.json()['content'][0]['id']
            assetname = response.json()['content'][0]['name']
            protectionpolicyid = response.json(
            )['content'][0]['protectionPolicyId']
            if protectionpolicyid is None:
                print('\nAsset {} not protected under any policy'.format(assetname))
                sys.exit()
            else:
                print('\nAsset id : {}, Asset Name : {}, Protection Policy id : {}'.format(
                    assetid, assetname, protectionpolicyid))
                return protectionpolicyid
    except requests.exceptions.RequestException:
        print('\nThe call {}{} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def get_policy_details(uri, accesstoken, protectionpolicyid):
    # Fetch the details of the protection policy retrieved in 3
    print('\nFetching protection policy')
    protectionpolicyendpoint = '/protection-policies/' + protectionpolicyid
    uri += protectionpolicyendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        # Call the Assets GET API with filter on type and name
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nFailed to get details of policy id: {}, code: {}, body: {}'.format(
                protectionpolicyid, response.status_code, response.text))
        print('\nProtection Policy: {}' .format(protectionpolicyid))
        print(response.text)
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def update_policy_schedule(uri, accesstoken, protectionpolicyid, jsonfile):
    # Update the schedule of the protection policy
    print('\nUpdating protection policy schedule: {}'.format(protectionpolicyid))
    updatepolicyendpoint = '/protection-policies/' + protectionpolicyid
    uri += updatepolicyendpoint
    # Read the json from a file
    payload = open(jsonfile, 'rb').read()
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        # Call the Login API with username and password
        response = requests.put(uri, headers=headers,
                                data=payload, verify=False)
        response.raise_for_status()
        if response.status_code not in [200, 201, 202]:
            raise Exception('\nFailed to update policy {}, code: {}, body: {}'.format(
                protectionpolicyid, response.status_code, response.text))
        print('\nProtection policy updated successfully')
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def logout(ppdm, user, uri, accesstoken):
    # Logout
    print('\nLogging out of the current session')
    logoutendpoint = '/logout'
    uri += logoutendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        response = requests.post(
            uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 204):
            raise Exception('\nLogout failed for user: {}, code: {}, body: {}'.format(
                user, response.status_code, response.text))
        print('\nUser: {} logged out of PPDM: {}'.format(user, ppdm))
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def main():
    port = '8443'
    apiendpoint = '/api/v2'
    args = get_args()
    ppdm = args.server
    user = args.user
    password = args.password
    assetname = args.assetname
    assettype = args.assettype
    action = args.action
    jsonfile = args.jsonfile
    uri = 'https://{}:{}{}'.format(ppdm, port, apiendpoint)
    accesstoken = authenticate(ppdm, user, password, uri)
    protectionpolicyid = get_asset_details(
        uri, accesstoken, assetname, assettype)
    if 'display_schedule' == action:
        get_policy_details(uri, accesstoken, protectionpolicyid)
    elif 'update_schedule' == action:
        update_policy_schedule(uri, accesstoken,
                               protectionpolicyid, jsonfile)
    logout(ppdm, user, uri, accesstoken)

if __name__ == "__main__":
    main()
