#!/usr/bin/env python3

import sys
import json
import uuid
from datetime import date
import argparse
import requests
import urllib3

# The purpose of this script is to simplify policy creation in PowerProtect
# Examples:
# python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list
# python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a create -n VMpolicy1 -asset prodVM1 -storage_name DD1 -freq daily -stime 11:00:00 -d 4 -ret "1 days"
# python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a create -n VMpolicy2 -asset testvm*,testapp1 -storage_name DD2 -dm TSDM -freq daily -stime 09:00:00 -d 2 -ret "3 days"


urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script to create protection policies in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-a', '--action', required=True, choices=["list", "list-raw", "create"],
                        help='Choose to list all Policies or create a new one')
    parser.add_argument('-t', '--type', required=False, action='store', default="vm",
                        help='The asset type - either vm or k8s')
    parser.add_argument('-n', '--name', required='create' in sys.argv, action='store', default=None,
                        help='The policy name')
    parser.add_argument('-id', '--id', required=False, action='store', default=None,
                        help='ID of the asset to be added to the policy')
    parser.add_argument('-asset', '--asset', action='store', default=None,
                        help='Name of the asset to be added to the Policy')
    parser.add_argument('-dm', '--data_mover', action='store', default="tsdm",
                        required=False, help='The VM data mover type - either TSDM or vADP')
    parser.add_argument('-storage_name', '--storage_name', required=False,
                        action='store', default=None,
                        help='The Data Domain name to use in the policy')
    parser.add_argument('-strgeid', '--storage_id', required=False,
                        action='store', default=None,
                        help='The Data Domain ID to use in the policy')
    parser.add_argument('-ddnic', '--datadomain_nic', required=False, default="fqdn",
                        action='store',
                        help='The Data Domain NIC to use in the policy')
    parser.add_argument('-freq', '--frequency', choices=["hourly", "daily", "weekly", "monthly"],
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


def get_version(uri, token):
    """Gets the PPDM version"""
    uri = f"{uri}/nodes"
    response = init_rest_call("GET", uri, token)
    if "version" in response["content"][0]:
        return response["content"][0]["version"]
    print("Could not determine PPDM version. Exiting...")
    raise SystemExit(1)


def get_policy(uri, token):
    """Get configured protection policies"""
    uri = f"{uri}/protection-policies"
    response = init_rest_call("GET", uri, token)
    return response["content"]


def check_policy(policies, name):
    """Checks if a policy exists by name"""
    for policy in policies:
        if name == policy["name"]:
            return True
    return False


def get_asset(uri, token, name, asset_id, asset_type):
    """Gets protected VMs"""
    uri = f"{uri}/assets"
    query = f'type eq "{asset_type}"'
    query += ' and protectionpolicy_id eq null'
    if asset_id is not None:
        query += f' and id eq "{asset_id}"'
    if name is not None:
        if "*" in name:
            name = name.replace('*', '')
            query += f' and name lk "%{name}%"'
        else:
            query += f' and name eq "{name}"'
    query_params = {'filter': query}
    response = init_rest_call("GET", uri, token, False, query_params)
    return response["content"]


def get_storage(uri, token, storage_name, storage_id):
    """Get Data Domain storage systems"""
    uri = f"{uri}/storage-systems"
    query = 'type eq "DATA_DOMAIN_SYSTEM"'
    if storage_id is not None:
        query += f' and id lk "%{storage_id}%"'
    if storage_name is not None:
        query += f' and name lk "%{storage_name}%"'
    query_params = {'filter': query}
    response = init_rest_call("GET", uri, token, False, query_params)
    return response["content"]


def extract_datadomain_nic(storage_list, dd_nic):
    """Finds the Data Domain ID and NIC"""
    storage = {"id": storage_list[0]["id"]}
    data_nic = None
    for nic in storage_list[0]["details"]["dataDomain"]["preferredInterfaces"]:
        if nic["networkName"].lower() == dd_nic.lower():
            storage["nic"] = nic["networkName"]
            break
        if "DATA" in nic["purposes"]:
            data_nic = nic["networkName"]
    if "nic" not in storage and data_nic:
        storage["nic"] = data_nic
    return storage


def build_schedule(freq, starttime, interval, duration, weekdays, daymonth):
    """Builds the schedule JSON"""
    cdate = date.today().strftime("%Y-%m-%d")
    if not duration.isdigit():
        print("Please specify duration in full hours")
        print("For example: 5")
        raise SystemExit(5)
    duration = int(duration)
    if not 1 <= duration <= 24:
        print("Please specify duration of up to 24 hours")
        print("For example: 5")
        raise SystemExit(5)
    schedule = {
        "frequency": freq.upper(),
        "startTime": f"{cdate}T{starttime}Z",
        "duration": f"PT{duration}H"
    }
    if freq == "hourly":
        schedule["interval"] = interval
    elif freq == "weekly":
        schedule["weekDays"] = str(weekdays).upper()
    elif freq == "monthly":
        schedule["dayOfMonth"] = daymonth
    return schedule


def build_schedule_v3(freq, starttime, interval, duration, weekdays, daymonth):
    """Builds the schedule JSON"""
    cdate = date.today().strftime("%Y-%m-%d")
    if not duration.isdigit():
        print("Please specify duration in full hours")
        print("For example: 5")
        raise SystemExit(5)
    duration = int(duration)
    if not 1 <= duration <= 24:
        print("Please specify duration of up to 24 hours")
        print("For example: 5")
        raise SystemExit(5)
    schedule = {
        "recurrence": {
            "pattern": {
                "type": freq.upper()
            }
        },
        "window": {
            "startTime": f"{cdate}T{starttime}Z",
            "duration": f"PT{duration}H"
        }
    }
    if freq == "hourly":
        schedule["recurrence"]["pattern"]["interval"] = interval
    elif freq == "weekly":
        schedule["recurrence"]["pattern"]["daysOfWeek"] = str(weekdays).upper()
    elif freq == "monthly":
        schedule["recurrence"]["pattern"]["dayOfMonth"] = daymonth
    return schedule


def build_retention(retention, legacy=None):
    """Builds the v3 retention JSON"""
    retlist = retention.split(' ')
    if not retlist[0].isdigit():
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        raise SystemExit(5)
    if len(retlist) != 2:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        raise SystemExit(5)
    if retlist[1][:-1].lower() not in ["day", "week", "month"]:
        print("Please specify retention in the format of 'number UNIT'")
        print("For example: 5 days")
        raise SystemExit(5)
    if retlist[1][-1].lower() == 's':
        retlist[1] = retlist[1][:-1].upper()
    if not legacy:
        retentionj = {
            "id": str(uuid.uuid4()),
            "time": [{
                "unitValue": int(retlist[0]),
                "unitType": retlist[1],
                "type": "RETENTION"
                }]
        }
    else:
        retentionj = {
            "interval": int(retlist[0]),
            "unit": retlist[1].upper(),
            "storageSystemRetentionLock": False
        }
    return retentionj


def build_policy_json(name, schedule, retention, storage, asset_type, data_mover):
    """Builds the policy JSON"""
    policy = {
        "name": name,
        "assetType": asset_type,
        "type": "ACTIVE",
        "encrypted": True,
        "enabled": True,
        "priority": 1,
        "dataConsistency": "CRASH_CONSISTENT",
        "stages": [{}]
    }
    policy["stages"][0] = {
        "id": str(uuid.uuid4()),
        "type": "PROTECTION",
        "passive": False,
        "target": {
            "storageSystemId": storage["id"]
        },
        "operations": [{}],
        "retention": retention
    }
    policy["stages"][0]["operations"][0] = {
        "type": "AUTO_FULL",
        "schedule": schedule
    }
    if asset_type == "VMWARE_VIRTUAL_MACHINE":
        policy["stages"][0]["attributes"] = {
            "vm": {
                "dataMoverType": data_mover
            }
        }
        policy["details"] = {
            "vm": {
                "protectionEngine": "VMDIRECT"
            }
        }
        if data_mover == "SDM":
            policy["stages"][0]["attributes"]["vm"].update({
                "disableQuiescing": True,
                "excludeSwapFiles": False,
                "appConsistentProtection": False
            })
    return policy


def build_policy_json_v3(name, schedule, retention, storage, asset_type, data_mover):
    """Builds the policy v3 JSON"""
    policy = {
        "name": name,
        "assetType": asset_type,
        "disabled": False,
        "purpose": "CENTRALIZED",
        "objectives": [{}]
    }
    policy["objectives"][0] = {
        "id": str(uuid.uuid4()),
        "config": {
            "dataConsistency": "CRASH_CONSISTENT"
        },
        "type": "BACKUP",
        "operations": [{}],
        "retentions": [retention],
        "target": {
            "preferredInterfaceId": storage["nic"],
            "storageContainerId": storage["id"]
        }
    }
    if asset_type == "VMWARE_VIRTUAL_MACHINE":
        policy["objectives"][0]["config"]["backupMechanism"] = data_mover
        if data_mover == "SDM":
            policy["objectives"][0]["options"] = {
                "disableQuiescing": True,
                "excludeSwapFiles": False,
                "appConsistentProtection": False,
                "indexingEnabled": False
            }
    policy["objectives"][0]["operations"][0] = {
        "id": str(uuid.uuid4()),
        "backupLevel": "SYNTHETIC_FULL",
        "schedule": schedule
    }
    return policy


def create_policy(uri, token, policy_data):
    """Creates policy based on the policy JSON"""
    uri = f"{uri}/protection-policies"
    response = init_rest_call("POST", uri, token, policy_data)
    if "id" in response:
        return response["id"]
    print("Could not create policy. Exiting...")
    raise SystemExit(1)


def assign_asset(uri, token, asset_id, policy_id):
    """Assigns an asset to a policy"""
    uri = f"{uri}/protection-policies/{policy_id}/asset-assignments"
    response = init_rest_call("POST", uri, token, asset_id)
    return response


def main():
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_release = 19.16
    api_v3_endpoint = "/api/v3"
    api_v3 = False

    args = get_args()
    ppdm, user, password = args.server, args.user, args.password
    action, name, asset_id, data_mover = args.action, args.name, args.id, args.data_mover
    asset, asset_type, storage_name = args.asset, args.type, args.storage_name
    storage_id, freq, starttime = args.storage_id, args.frequency, args.starttime
    interval, duration, weekdays = args.interval, args.duration, args.weekdays
    daymonth, retention, dd_nic = args.daymonth, args.retention, args.datadomain_nic

    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(uri, user, password)
    version = get_version(uri, token)

    if float(version[:5]) > api_v3_release:
        print("Using The PowerProtect Data Manager v3 API")
        api_v3 = True
        uri_v3 = f"https://{ppdm}:{api_port}{api_v3_endpoint}"
        policies = get_policy(uri_v3, token)
    else:
        policies = get_policy(uri, token)

    if action in ("list", "list-raw"):
        if action == "list-raw":
            print(json.dumps(policies, indent=4))
        else:
            for policy in policies:
                print("------------------------------------------------------")
                print("Policy Name:", policy["name"])
                print("Policy ID:", policy["id"])
                print("Policy Type:", policy["assetType"])
                if api_v3:
                    print("Policy Disabled:", policy["disabled"])
                    print("Number of Objectives:", len(policy["objectives"]))
                else:
                    print("Policy Enabled:", policy["enabled"])
                    print("Number of Assets:", policy["summary"]["numberOfAssets"])
                    print("Number of Stages:", len(policy["stages"]))
                print()
    else:
        asset_type = asset_type.lower()
        data_mover = data_mover.lower()
        no_asset = False
        if (asset is None and asset_id is None):
            print("Creating a policy without any assets")
            no_asset = True
        if asset_type not in ("vm", "k8s"):
            print("Defaulting to VMware VM asset type")
            asset_type = "VMWARE_VIRTUAL_MACHINE"
        elif asset_type == "vm":
            asset_type = "VMWARE_VIRTUAL_MACHINE"
        elif asset_type == "k8s":
            asset_type = "KUBERNETES"

        if data_mover.lower() not in ("tsdm", "vadp"):
            data_mover = "SDM"
        elif data_mover == "tsdm":
            data_mover = "SDM"
        elif data_mover == "vadp":
            data_mover = "VADP"

        if storage_name is None and storage_id is None:
            print("Please specify either storage name or ID")
            raise SystemExit(1)
        if None in [starttime, duration, retention]:
            print("Make sure that starttime, duration and retention parameters are set")
            raise SystemExit(1)
        freq = freq.lower()
        if freq == "hourly" and interval is None:
            print("Make sure that the interval is set")
            raise SystemExit(1)
        if freq == "weekly" and weekdays is None:
            print("Make sure that weekdays parameters is set")
            raise SystemExit(1)
        if freq == "monthly" and daymonth is None:
            print("Make sure that the daymonth parameters is set")
            raise SystemExit(1)

        storage_list = get_storage(uri, token, storage_name, storage_id)
        if len(storage_list) > 1:
            print(f"Storage Name {storage_name} yielded in more than 1 result")
            print("Narrow down the results using the --storage_name and --storage_id paramaters")
            raise SystemExit(5)
        storage = extract_datadomain_nic(storage_list, dd_nic)

        if check_policy(policies, name):
            print(f"Policy {name} already exists, pick a different name")
            raise SystemExit(5)

        if api_v3:
            schedule = build_schedule_v3(freq, starttime, interval, duration, weekdays, daymonth)
            retention = build_retention(retention)
            policy_data = build_policy_json_v3(name, schedule, retention, storage, asset_type, data_mover)
            policy_id = create_policy(uri_v3, token, policy_data)
        else:
            schedule = build_schedule(freq, starttime, interval, duration, weekdays, daymonth)
            retention = build_retention(retention, True)
            policy_data = build_policy_json(name, schedule, retention, storage, asset_type, data_mover)
            policy_id = create_policy(uri, token, policy_data)
        print(f"Policy: {name} created successfully")

        if no_asset:
            print("Skipping asset assignment")
        else:
            assets = asset.split(',')
            asset_list = []
            for asset in assets:
                asset = asset.strip()
                asset_data = get_asset(uri, token, asset, asset_id, asset_type)
                if len(asset_data) == 0:
                    print(f"Asset {asset} could not be found")
                else:
                    for spec_asset in asset_data:
                        if spec_asset["status"] != "AVAILABLE":
                            print(f"Asset {spec_asset["name"]} could not be added:", end=' ')
                            print(f"asset status is {spec_asset["status"]}")
                        else:
                            asset_list.append(spec_asset["id"])
                            print(f"Assigning asset: {spec_asset['name']} to policy: {name}")
            if assign_asset(uri, token, asset_list, policy_id):
                print(f"All assets successfully assigned to policy: {name}")


if __name__ == "__main__":
    main()
