#!/usr/bin/env python3

import argparse
import requests
import json
import sys
import urllib3
from sys import argv
import time

# The purpose of this script to facilitiate restore of a VM to its original location

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
    parser.add_argument('-n', '--vmname', required=True, action='store',
                        help='The name of the VM to recover')
    parser.add_argument('-a', '--action', choices=['get_backups', 'recover'],
                         default='get_backups', required=True,
                         help='Get the list of backups or recover using a backup ID')
    parser.add_argument('-bckid','--backupid', required=('recover' in argv),
                         help='The ID of the backup to recover from')
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

def get_protected_vm(ppdm, uri, token, vmname):
    # Returns the VM based on its name
    suffixurl = "/assets"
    uri += suffixurl
    vmfilter = "VMWARE_VIRTUAL_MACHINE"
    protectedfilter="protectionPolicyId ne null"
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'type eq "{}" and name lk "{}" and {}'.format(vmfilter, vmname, protectedfilter)
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

def get_backups(ppdm, uri, token, vmid, name):
    # Returns a list of backups for a given
    suffixurl = "/copies"
    prefixurl = "/assets"
    uri += "{}/{}{}".format(prefixurl, vmid, suffixurl)
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 200):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    assetlist = response.json()["content"]
    for elem in assetlist:
        print("---------------------------------------------------------")
        print("         Backup ID:", elem["id"])
        print("     Creation Time:", elem["createTime"])
        print("       Backup Size:", elem["size"])
        print("         Copy Type:", elem["copyType"])
        print("    Retention Time:", elem["retentionTime"])
        print("      Adhoc Backup:", elem["adhocBackup"])
        print(" Backup Array Type:", elem["details"]["arraySubType"])
        print("   Array Serial No:", elem["details"]["arraySerialNo"])
        print()

def recover_vm_to_orig(ppdm, uri, token, copyid, name):
    # Recovers a VM to its original location
    suffixurl = "/restored-copies"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    desc = 'Restore {} to original production'.format(name)
    payload = json.dumps({
			'description' : desc,
			'copyId' : copyid,
			'restoreType': 'TO_PRODUCTION'
		})
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    if (response.status_code != 201):
        raise Exception('Failed to query {}, code: {}, body: {}'.format(
				uri, response.status_code, response.text))
    if 'activityId' in response.json():
        return response.json()['activityId']
    if 'taskId' in response.json():
        return response.json()['taskId']
    if 'jobId' in response.json():
        return response.json()['jobId']
    return None

def monitor_activity(ppdm, uri, token, activityid):
    # Monitors an activity by its ID
    timeout = 1800 # 30 minutes timeout
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
    ppdm, user, password, vmname, action = args.server, args.user, args.password, args.vmname, args.action
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    token = authenticate(ppdm, user, password, uri)
    vms = get_protected_vm(ppdm, uri, token, vmname)
    if len(vms) == 0:
        print('No Virtual Machine name matches the name criteria: {}'.format(vmname))
    elif len(vms) > 1:
        print('Found more than one Virtual Machine which matches: {}'.format(vmname))
        for vm in vms:
            print('{} : {}'.format(vm['name'], vm['id']))
        print('Please specify the exact Virtual Machine name')
    else:
        vmid = vms[0]['id']
        name = vms[0]['name']
        if (action == "get_backups"):
            get_backups(ppdm, uri, token, vmid, name)
        elif action == "recover":
            copyid = args.backupid
            activityid = recover_vm_to_orig(ppdm, uri, token, copyid, name)
            result = monitor_activity(ppdm, uri, token, activityid)
            print('Restore activity {} status {}'.format(activityid, result))
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
