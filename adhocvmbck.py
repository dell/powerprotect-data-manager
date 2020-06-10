#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json
import time

# The purpose of this script is to facilitate ad-hoc VM backup in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to perform ad-hoc VM backup in PowerProtect')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'backup', 'monitor'],
                        help='Choose to list all protected VMs or ad-hoc backup a VM')
    parser.add_argument('-n', '--name', required=('backup' in sys.argv and '-id' not in sys.argv),
                        action='store', default=None,
                        help='Name of the VM to backup')
    parser.add_argument('-id', '--id', required=('backup' in sys.argv and '-n' not in sys.argv),
                        action='store',
                        default=None, help='Optionally provide the Asset ID to backup')
    parser.add_argument('-activity_id', '--activity_id', required=('monitor' in sys.argv and '-aidfile' not in sys.argv),
                        action='store',
                        help='Optionally provide the Asset ID to monitor')
    parser.add_argument('-full', '--full', required=False, action='store_true',
                        default=False, help='Optionally force full VM backup')
    parser.add_argument('-nmonitor', '--no-monitor', required=False, action='store_true', dest='nmonitor',
                        default=False, help='Optionally prevents monitoring of backup process')
    parser.add_argument('-aidfile', '--activity-id-file', required=('monitor' in sys.argv and '-activity_id' not in sys.argv),
                        action='store', dest='aidfile', default=None,
                        help='Optionally provide a file to retrieve the activity ID to monitor')
    parser.add_argument('-outfile', '--output-file', required=False, action='store', dest='outfile',
                        default=None, help='Optionally provide a file to save the asset and activity ID to')
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

def get_asset(uri, token, name, id):
    suffixurl = "/assets"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'type eq "VMWARE_VIRTUAL_MACHINE"'
    filter += ' and protectionPolicyId ne null'
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

def adhoc_backup(uri, token, id, full):
    # Performs ad-hoc backup of a VM by name or ID
    suffixurl = "/asset-backups"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    if not full:
        backuptype = "FULL"
    else:
        backuptype = "AUTO_FULL"
    payload = json.dumps({
        'assetId' : '{}'.format(id),
		'backupType' : backuptype
		})
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202]:
        print('Failed to run ad-hoc backup on asset ID {}, code: {}, body: {}'.format(
				id, response.status_code, response.text))
    if 'activityId' in response.json():
        return response.json()['activityId']
    if 'taskId' in response.json():
        return response.json()['taskId']
    if 'jobId' in response.json():
        return response.json()['jobId']
    return None

def monitor_activity(uri, token, activityid):
    # Monitors an activity by its ID
    timeout = 300 # 5 minutes timeout
    interval = 10 # 10 seconds interval
    suffixurl = "/activities/"
    uri += suffixurl + str(activityid)
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
            print('Failed to query {}, code: {}, body: {}'.format(
                uri, response.status_code, response.text))
            return None
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
    ppdm, user, password, action, name, id = args.server, args.user, args.password, args.action, args.name, args.id
    full, nmonitor, aid, aidfile, outfile = args.full, args.nmonitor, args.activity_id, args.aidfile, args.outfile
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    token = authenticate(ppdm, user, password, uri)
    if (action == 'monitor'):
        if aidfile is not None:
            file = open(aidfile, 'r')
            aid = file.read().rstrip()
            file.close()
        monitor_activity(uri, token, aid)
    else:
        vms = get_asset(uri, token, name, id)
        if len(vms) == 0:
            print('Virtual Machine asset could not be found')
        if (action == 'list'):
            for asset in vms:
                print("---------------------------------------------------------")
                print("Asset ID:", asset["id"])
                print("Asset Name:", asset["name"])
                print("Asset Type:", asset["type"])
                print("Last Backup Time:", asset["lastAvailableCopyTime"])
                print()
        elif (len(vms) > 1):
            print ("VM Name {} yielded in more than 1 result".format(name))
            print("Narrow down the results using the --action list paramater")
        elif (len(vms) == 1):
            print("Performing Ad-hoc backup for VM", vms[0]["name"])
            activityid = adhoc_backup(uri, token, vms[0]["id"], full)
            if (activityid is None):
                next
            elif (not nmonitor):
                monitor_activity(uri, token, activityid)
            else:
                print("Activity ID:", activityid)
                if (outfile is not None):
                    file = open(outfile, 'w')
                    file.write(activityid)
                    file.close()
                    print("Activity ID logged to file",outfile)
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
