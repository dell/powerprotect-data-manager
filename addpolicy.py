#!/usr/bin/env python3

import argparse
import requests
import urllib3
import sys
import json
import uuid
import time
from datetime import date
    
# The purpose of this script is to simplify Policy creation in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to create Protection Lifecycle Policies in PowerProtect')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'create'],
                        help='Choose to list all Policies or to create a new Policy')
    parser.add_argument('-n', '--name', required='create' in sys.argv, action='store', default=None,
                        help='Name of Policy')
    parser.add_argument('-id', '--id', required=False, action='store', default=None,
                        help='ID of the asset to be added to the Policy')
    parser.add_argument('-asset', '--asset', action='store', default=None,
                        help='Name of the asset to be added to the Policy')
    parser.add_argument('-storagename', '--storagename', required=False,
                        action='store', default=None,
                        help='Name of the Storage to be configured in the Policy')
    parser.add_argument('-storgeid', '--storageid', required=False,
                        action='store', default=None,
                        help='ID of the Storage to be configured in the Policy')
    parser.add_argument('-freq', '--frequency', choices=['hourly', 'daily', 'weekly', 'monthly'],
                        help='Backup frequency')
    parser.add_argument('-i', '--interval', action='store',
                        default=None, help='Hourly interval')
    parser.add_argument('-stime', '--starttime',
                        action='store', default=None, help='Start Time (24hr)')
    parser.add_argument('-d', '--duration', action='store', 
                        default=None, help='Duration in hours')
    parser.add_argument('-wkd', '--weekdays', required=False,
                        action='store', default=None, help='Week days')
    parser.add_argument('-dmon', '--daymonth', required='monthly' in sys.argv,
                        action='store', default=None, help='Comma-seperated list of days in month')
    parser.add_argument('-ret', '--retention', action='store',
                        help='Retention in either day, week or month units')
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

def get_policy(uri, token):
    # Get configured Policys
    suffixurl = "/protection-policies"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    try:
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {}{} failed with exception:{}".format(response.request.method, response.url, err))
    return response.json()['content']

def get_asset(uri, token, name, id):
    # Get protected VMs
    suffixurl = "/assets"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'type eq "VMWARE_VIRTUAL_MACHINE"'
    filter += ' and protectionPolicyId eq null'
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

def get_storage(uri, token, storagename, storageid):
    # Get DD storage systems
    suffixurl = "/storage-systems"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'type eq "DATA_DOMAIN_SYSTEM"'
    if storageid != None:
            filter += ' and id lk "%{}%"'.format(storageid)
    if storagename != None:
        filter += ' and name lk "%{}%"'.format(storagename)
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

def build_schedule(freq, starttime, interval, duration, weekdays, daymonth):
    # Builds the schedule JSON
    cdate = date.today().strftime("%Y-%m-%d")
    if not duration.isdigit():
        print ("Please specify duration in full hours")
        print ("For example: 5")
        sys.exit(5)
    if not (1 <= int(duration) <= 24):
        print ("Please specify duration of up to 24 hours")
        print ("For example: 5")
        sys.exit(5)
    schedule = {}
    if freq.lower() == 'hourly':
        schedule['frequency'] = 'HOURLY'
        schedule['interval'] = interval
        schedule['starttime'] = '{}T{}Z'.format(cdate, starttime)
        schedule['duration'] = 'PT{}H'.format(duration)
    elif freq.lower() == 'daily':
        schedule['frequency'] = 'DAILY'
        schedule['starttime'] = '{}T{}Z'.format(cdate, starttime)
        schedule['duration'] = 'PT{}H'.format(duration)
    elif freq.lower() == 'weekly':
        schedule['frequency'] = 'WEEKLY'
        schedule['starttime'] = '{}T{}Z'.format(cdate, starttime)
        schedule['duration'] = 'PT{}H'.format(duration)
        schedule['weekDays'] = str(weekdays).upper()
    elif freq.lower() == 'monthly':
        schedule['frequency'] = 'MONTHLY'
        schedule['dayOfMonth'] = daymonth
        schedule['starttime'] = '{}T{}Z'.format(cdate, starttime)
        schedule['duration'] = 'PT{}H'.format(duration)
    return schedule

def build_retention(retention):
    # Builds the retention JSON
    retlist = retention.split(' ')
    if not retlist[0].isdigit():
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        sys.exit(5)
    if len(retlist) > 2:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        sys.exit(5)
    if retlist[1][:-1].lower() not in ['day', 'week', 'month']:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        sys.exit(5)
    if retlist[1][-1] == 's':
        retlist[1] = retlist[1][:-1].upper()
    retentionj = {}
    retentionj['interval'] = retlist[0]
    retentionj['unit'] = retlist[1].upper()
    retentionj['storageSystemRetentionLock'] = 'false'
    return retentionj

def build_policy_json(name, schedule, retention, storageid):
    # Builds the Policy JSON
    priority = 1
    stagetype = "AUTO_FULL"
    policy = {}
    policy['name'] = name
    policy['assetType'] = "VMWARE_VIRTUAL_MACHINE"
    policy['type'] = "ACTIVE"
    policy['encrypted'] = False
    policy['enabled'] = True
    policy['priority'] = priority
    policy['dataConsistency'] = "CRASH_CONSISTENT"
    policy['details'] = {}
    policy['details']["vm"] = {}
    policy['details']["vm"]['protectionEngine'] = "VMDIRECT"
    policy['stages'] = [None]
    policy['stages'][0] = {}
    policy['stages'][0]['id'] = str(uuid.uuid4())
    policy['stages'][0]['type'] = "PROTECTION"
    policy['stages'][0]['passive'] = False
    policy['stages'][0]['target'] = {}
    policy['stages'][0]['target']['storageSystemId'] = storageid
    policy['stages'][0]['operations'] = [None]
    policy['stages'][0]['operations'][0] = {}
    policy['stages'][0]['operations'][0]['type'] = str(stagetype)
    policy['stages'][0]['operations'][0]['schedule'] = schedule
    policy['stages'][0]['retention'] = retention
    return json.dumps(policy)

def create_policy(uri, token, policyjson):
    # Create Policy based on the previously built JSON
    suffixurl = "/protection-policies"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    payload = policyjson
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202]:
        raise Exception('Failed to create Policy: {}, code: {}, body: {}'.format(json.loads(policyjson)["name"],
				response.status_code, response.text))
        print("Policy: {} created successfully".format(json.loads(policyjson)["name"]))
    return response.json()['id']

def get_asset(uri, token, asset, id):
    # Get asset by name and/or ID
    suffixurl = "/assets"
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    filter = 'type eq "VMWARE_VIRTUAL_MACHINE"'
    filter += ' and protectionPolicyId eq null'
    if id != None:
        filter += ' and id lk "%{}%"'.format(id)
    if asset != None:
        filter += ' and name lk "%{}%"'.format(asset)
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

def assign_asset(uri, token, id, policyid):
    # Assigns the asset to the Policy
    suffixurl = "/protection-policies/{}/asset-assignments".format(policyid)
    uri += suffixurl
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(token)}
    payload = json.dumps(id)
    try:
        response = requests.post(uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        print("The call {} {} failed with exception:{}".format(response.request.method, response.url, err))
    if response.status_code not in [200, 201, 202, 204]:
        print('Failed to assign asset with ID {}, code: {}, body: {}'.format(
            id, response.status_code, response.text))
    return None

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
    name, id, asset, storagename, storageid = args.name, args.id, args.asset, args.storagename, args.storageid
    freq, starttime, interval = args.frequency, args.starttime, args.interval
    duration, weekdays, daymonth, retention = args.duration, args.weekdays, args.daymonth, args.retention
    uri = "https://{}:{}{}".format(ppdm, port, apiendpoint)
    token = authenticate(ppdm, user, password, uri)
    if action == 'list':
        policies = get_policy(uri, token)
        for policy in policies:
            print("---------------------------------------------------------")
            print("Policy Name:", policy["name"])
            print("Policy ID:", policy["id"])
            print("Policy Type:", policy["assetType"])
            print("Policy State:", policy["type"])
            print("Policy Enabled:", policy["enabled"])
            print("Number of Assets:", policy["summary"]["numberOfAssets"])
            print("Number of Stages:", len(policy["stages"]))
            print()
    else:
        if (asset is None and id is None):
            print("Please specify either asset name or ID")
            sys.exit(1)
        if (storagename is None and storageid is None):
            print("Please specify either storage name or ID")
            sys.exit(1)
        if (None in [starttime, duration, retention]):
            print("Make sure that starttime, duration and retention parameters are set")
            sys.exit(1)
        if (freq == 'hourly') and (interval is None):
            print("Make sure that the interval is set")
            sys.exit(1)
        if (freq == 'weekly') and (weekdays is None):
            print("Make sure that weekdays parameters is set")
            sys.exit(1)
        if (freq == 'monthly') and (daymonth is None):
            print("Make sure that the daymonth parameters is set")
            sys.exit(1)
        storagelist = get_storage(uri, token, storagename, storageid)
        if len(storagelist) > 1:
            print("Storage Name {} yielded in more than 1 result".format(storagename))
            print("Narrow down the results using the --storagename and --storageid paramaters")
            sys.exit(5)
        storageid = storagelist[0]['id']
        schedule = build_schedule(freq, starttime, interval, duration, weekdays, daymonth)
        retention = build_retention(retention)
        policyjson = build_policy_json(name, schedule, retention, storageid)
        policyid = create_policy(uri, token, policyjson)
        print("Policy: {} created successfully".format(name))
        vms = get_asset(uri, token, asset, id)
        if len(vms) == 0:
            print('Virtual Machine asset could not be found')
        else:
            assets = []
            for vm in vms:
                assets.append(vm["id"])
                print("Assigning asset: \"{}\" to Policy: \"{}\"".format(vm["name"], name))
        assign_asset(uri, token, assets, policyid)
    logout(ppdm, user, uri, token)

if __name__ == "__main__":
    main()
