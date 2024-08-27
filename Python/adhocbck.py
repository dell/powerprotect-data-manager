#!/usr/bin/env python3

import argparse
import sys
import json
import time
import requests
import urllib3

# This script facilitates ad-hoc backups in PowerProtect Data Manager
# Author - Idan Kentor <idan.kentor@dell.com>
# Copyright [2024] [Idan Kentor]

# Examples:
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n VM1
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n VM2 -ret "1 days" -full
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list -t k8s
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n k8s-ns1 -t k8s
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list -t pmax
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n sg1 -t pmax -ret "2 months"


urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script for ad-hoc backups in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=['list', 'backup', 'monitor', 'list-raw'],
                        help='Choose to list all protected VMs or ad-hoc backup a VM')
    parser.add_argument('-n', '--name', required=('backup' in sys.argv and '-id' not in sys.argv),
                        action='store', default=None,
                        help='Name of the VM to backup')
    parser.add_argument('-t', '--type', required=False,
                        action='store', default="vm",
                        help='Specify the asset type = VM, PMAX or K8s')
    parser.add_argument('-id', '--id', required=('backup' in sys.argv and '-n' not in sys.argv),
                        action='store',
                        default=None, help='Optionally provide the Asset ID to backup')
    parser.add_argument('-activity_id', '--activity_id', required=('monitor' in sys.argv and '-aidfile' not in sys.argv),
                        action='store',
                        help='Optionally provide the Asset ID to monitor')
    parser.add_argument('-full', '--full', required=False, action='store_true',
                        default=False, help='Optionally force full VM backup')
    parser.add_argument('-ret', '--retention', action='store',
                        help='Optionally specify retention in either day, week or month units')
    parser.add_argument('-nmonitor', '--no-monitor', required=False, action='store_true', dest='nmonitor',
                        default=False, help='Optionally prevents monitoring of backup process')
    parser.add_argument('-aidfile', '--activity-id-file', required=('monitor' in sys.argv and '-activity_id' not in sys.argv),
                        action='store', dest='aidfile', default=None,
                        help='Optionally provide a file to retrieve the activity ID to monitor')
    parser.add_argument('-outfile', '--output-file', required=False, action='store', dest='outfile',
                        default=None, help='Optionally provide a file to save the asset and activity ID to')
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


def authenticate(ppdm, user, password, uri):
    """PPDM login"""
    uri = f"{uri}/login"
    payload = {"username": user, "password": password}
    token = init_rest_call("POST", uri, payload, payload)
    if token:
        print(f"Login for user: {user} to PPDM: {ppdm}")
        return token
    print(f"Cannot login to PPDM {ppdm}")
    raise SystemExit(1)


def get_version(uri, token):
    """Gets the PPDM version"""
    uri = f"{uri}/nodes"
    response = init_rest_call("GET", uri, token)
    if "version" in response["content"][0]:
        return response["content"][0]["version"]
    print("Could not determine PPDM version. Exiting...")
    raise SystemExit(1)


def get_asset(uri, token, name, asset_type, asset_id):
    """Gets asset by type or ID"""
    suffixurl = "/assets"
    uri += suffixurl
    if asset_type.lower() == "vm":
        query = 'type eq "VMWARE_VIRTUAL_MACHINE"'
    elif asset_type.lower() == "pmax":
        query = 'type eq "POWER_MAX_BLOCK" and subtype eq "POWER_MAX_STORAGE_GROUP"'
    elif asset_type.lower() == "k8s":
        query = 'type eq "KUBERNETES" and subtype eq "K8S_NAMESPACE"'
    if asset_id is not None:
        query += f' and id lk "{asset_id}"'
    if name is not None:
        query += f' and name lk "{name}"'
    params = {"filter": query}
    response = init_rest_call("GET", uri, token, None, params)
    return response["content"]


def extract_stage_id(uri, token, policy_id):
    """Finds the protection stage ID of a given protection policy"""
    uri = f"{uri}/protection-policies/{policy_id}"
    response = init_rest_call("GET", uri, token)
    if "stages" in response:
        for stage in response["stages"]:
            if stage["type"] == "PROTECTION":
                return stage["id"]
    else:
        print("Could not retrieve the backup stage in the proteciton policy")
        raise SystemExit(1)


def extract_stage_id_v3(uri, token, policy_id):
    """Finds the protection stage ID of a given protection policy - v3 API"""
    uri = f"{uri}/protection-policies/{policy_id}"
    response = init_rest_call("GET", uri, token)
    if "objectives" in response:
        for objective in response["objectives"]:
            if objective["type"] == "BACKUP":
                return objective["id"]
    else:
        print("Could not retrieve the backup stage in the proteciton policy")
        raise SystemExit(1)


def build_retention(retention, api_v3=None):
    """Builds the retention JSON for both API versions"""
    ret_lock = False
    ret_list = retention.split(' ')
    if not ret_list[0].isdigit():
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        raise SystemExit(5)
    if len(ret_list) > 2:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        raise SystemExit(5)
    if ret_list[1][-1] == 's':
        ret_list[1] = ret_list[1][:-1]
    if ret_list[1].lower() not in ['day', 'week', 'month']:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        print(ret_list[1])
        raise SystemExit(5)
    if api_v3:
        timej = [{}]
        timej[0]["type"] = "RETENTION"
        timej[0]["unitValue"] = int(ret_list[0])
        timej[0]["unitType"] = ret_list[1].upper()
        retentionj = [{}]
        retentionj[0]["time"] = timej
        return retentionj
    retentionj = {}
    retentionj["interval"] = int(ret_list[0])
    retentionj["unit"] = ret_list[1].upper()
    retentionj["storageSystemRetentionLock"] = ret_lock
    return retentionj


def build_protection_payload(asset_id, stage_id, retention, backup_type):
    """Builds the required payload for the adhoc protection call"""
    protect_payload = {}
    protect_payload["assetIds"] = [asset_id]
    protect_payload["stages"] = [{}]
    protect_payload["stages"][0]["id"] = stage_id
    if retention:
        retention = build_retention(retention)
        protect_payload["stages"][0]["retention"] = retention
    protect_payload["stages"][0]["operation"] = {}
    if backup_type:
        protect_payload["stages"][0]["operation"]["backupType"] = "FULL"
    else:
        protect_payload["stages"][0]["operation"]["backupType"] = "SYNTHETIC_FULL"
    return protect_payload


def build_protection_payload_v3(asset_id, policy_id, stage_id, retention, backup_type):
    """Builds the required payload for the adhoc protection call - v3 API"""
    protect_payload = {}
    protect_payload["source"] = {"assetIds": [asset_id]}
    protect_payload["policy"] = {}
    protect_payload["policy"]["id"] = policy_id
    protect_payload["policy"]["objectives"] = [{}]
    protect_payload["policy"]["objectives"][0]["id"] = stage_id
    if backup_type:
        protect_payload["policy"]["objectives"][0]["operation"] = {
            "backupLevel": "FULL"
            }
    else:
        protect_payload["policy"]["objectives"][0]["operation"] = {
            "backupLevel": "SYNTHETIC_FULL"
            }
    if retention:
        retention = build_retention(retention, True)
        protect_payload["policy"]["objectives"][0]["retentions"] = retention
    return protect_payload


def adhoc_backup(uri, token, policy_id, protect_payload):
    """Performs ad-hoc backup of a VM by name or ID"""
    uri = f"{uri}/protection-policies/{policy_id}/protections"
    response = init_rest_call("POST", uri, token, protect_payload)
    try:
        return response.json()["results"][0]["activityId"]
    except (KeyError, AttributeError) as error:
        print("Ad-hoc protection call failed. Exiting...")
        raise SystemExit(1) from error


def adhoc_backup_v3(uri, token, protect_payload):
    """Performs ad-hoc backup of a VM by name or ID - API v3"""
    uri = f"{uri}/protections"
    response = init_rest_call("POST", uri, token, protect_payload)
    try:
        return response["results"][0]["activityId"]
    except (KeyError, AttributeError) as error:
        print("Ad-hoc protection call failed. Exiting...")
        raise SystemExit(1) from error


def monitor_activity(uri, token, activity_id):
    """Monitors an activity by its ID"""
    timeout = 1200  # 20 minutes timeout
    interval = 10  # 10 seconds interval
    uri = f"{uri}/activities/{str(activity_id)}"
    start = time.time()
    while True:
        if (time.time() - start) > timeout:
            break
        response = init_rest_call("GET", uri, token)
        timestamp = time.strftime("%m-%d-%y %H:%M:%S")
        print(f"Activity {activity_id} {response['state']} at {timestamp}")
        if response["state"] == "COMPLETED":
            duration_sec = response["duration"] / 1000
            duration_min = int(duration_sec // 60)
            duration_sec = round(duration_sec % 60, 2)
            print(f"Backup completed in {duration_min} minutes and {duration_sec} seconds")
            return response["result"]["status"]
        time.sleep(interval)
    return "TIMEOUT"


def main():
    # Const definition
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_release = 19.16
    api_v3_endpoint = "/api/v3"
    api_v3 = False

    # Args assignment
    args = get_args()
    ppdm, user, password = args.server, args.user, args.password
    action, name, asset_id = args.action, args.name, args.id
    full_bck, retention, nmonitor = args.full, args.retention, args.nmonitor
    aid, aidfile, outfile = args.activity_id, args.aidfile, args.outfile
    asset_type = args.type

    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(ppdm, user, password, uri)
    version = get_version(uri, token)
    if float(version[:5]) > api_v3_release:
        api_v3 = True
        uri_v3 = f"https://{ppdm}:{api_port}{api_v3_endpoint}"
    if action == "monitor":
        if aidfile is not None:
            with open(aidfile, "r", encoding="utf-8") as file_handle:
                try:
                    aid = file_handle.read().rstrip()
                except (OSError, FileNotFoundError) as error:
                    print("Could not get activity ID from file")
                    raise SystemExit(1) from error
            file_handle.close()
        monitor_activity(uri, token, aid)
    else:
        assets = get_asset(uri, token, name, asset_type, asset_id)
        if len(assets) == 0:
            print("Asset could not be found")
            raise SystemExit(1)
        if action == "list":
            for asset in assets:
                print("---------------------------------------------------------")
                print("Asset ID:", asset["id"])
                print("Asset Name:", asset["name"])
                print("Asset Type:", asset["type"])
                print("Last Backup Time:", asset["lastAvailableCopyTime"])
                print()
        elif action == "list-raw":
            print(json.dumps(assets, indent=4))
        elif len(assets) > 1:
            print(f"Asset name {name} yielded in more than 1 result")
            print("Narrow down the results using the id or type parameters")
        elif len(assets) == 1:
            timestamp = time.strftime("%m-%d-%y %H:%M:%S")
            print(f"Performing Ad-hoc backup for asset {assets[0]["name"]} at {timestamp}")
            policy_id = assets[0]["protectionPolicyId"]
            asset_id = assets[0]["id"]
            if api_v3:
                print("Using The PowerProtect Data Manager v3 API")
                stage_id = extract_stage_id_v3(uri_v3, token, policy_id)
                protect_payload = build_protection_payload_v3(asset_id, policy_id, stage_id, retention, full_bck)
                activity_id = adhoc_backup_v3(uri_v3, token, protect_payload)
            else:
                stage_id = extract_stage_id(uri, token, policy_id)
                protect_payload = build_protection_payload(asset_id, stage_id, retention, full_bck)
                activity_id = adhoc_backup(uri, token, policy_id, protect_payload)
            if not nmonitor:
                monitor_activity(uri, token, activity_id)
            else:
                print("Activity ID:", activity_id)
                if outfile is not None:
                    with open(outfile, "w", encoding="utf-8") as file_handle:
                        try:
                            file_handle.write(activity_id)
                        except (OSError, FileNotFoundError) as error:
                            print("Could not log activity ID to file")
                            raise SystemExit(1) from error
                    file_handle.close()
                    print("Activity ID logged to file:", outfile)


if __name__ == "__main__":
    main()
