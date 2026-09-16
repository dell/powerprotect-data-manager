#!/usr/bin/env python3

"""
Automate protection policy creation and asset assignment in Dell
PowerProtect Data Manager.

Author: Idan Kentor <idan.kentor@dell.com>
Version: 2 - September 2026
Copyright: [2026] [Idan Kentor]

Example usage:
    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list

    python addpolicy.py -s 10.0.0.1 -usr admin -envpassword -a list

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a list -tls

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n VMpolicy1 -asset prodVM1 -storage_name DD1 \
      -freq daily -stime 11:00:00 -d 4 -ret "1 days"

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n VMpolicy2 -asset testvm*,testapp1 -storage_name DD2 \
      -dm TSDM -freq daily -stime 09:00:00 -d 2 -ret "3 days"

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n HypervPolicy -t hyperv -asset hvhost01 \
      -storage_name DD1 -freq daily -stime 02:00:00 -d 3 -ret "5 days"

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n VMpolicyHourly -asset prodVM1 -storage_name DD1 \
      -freq hourly -stime 08:00:00 -d 4 -i 4 -ret "1 days"

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n ExistingPolicy1 -asset prodVM2 -existing

    python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
      -a create -n AHV-vmdev1 -asset vm-dev1 -exact -t nutanix \
      -storage_name DD1 -freq daily -stime 10:00:00 -ret "7 days"
"""

import argparse
import json
import logging
import logging.handlers
import os
import sys
import uuid
from datetime import date
import requests
import urllib3

logger = logging.getLogger("addpolicy")


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script to create protection policies in PowerProtect '
                     'Data Manager'
    )
    parser.add_argument('-s', '--server', required=True, action='store',
                         help='PPDM DNS name or IP')

    parser.add_argument('-usr', '--user', required=False, action='store',
                         default='admin', help='User')

    parser.add_argument('-pwd', '--password', required=False, action='store',
                         help='Password')

    parser.add_argument('-envpassword', '--env-password', required=False,
                         action='store_true', dest='envpassword',
                         help='Read password from PPDM_PASSWORD '
                              'environment variable')

    parser.add_argument('-a', '--action', required=True, action='store',
                         choices=["list", "list-raw", "create"],
                         help='Choose to list all Policies or create a '
                              'new one')

    parser.add_argument('-t', '--type', required=False, action='store',
                         default="vm",
                         help='The asset type - vm, hyperv, nutanix, '
                              'nativeedge or k8s')

    parser.add_argument('-n', '--name', required=False, action='store',
                         default=None, help='The policy name')

    parser.add_argument('-id', '--id', required=False, action='store',
                         default=None,
                         help='ID of the asset to be added to the policy')

    parser.add_argument('-asset', '--asset', action='store', default=None,
                         help='Name of the asset to be added to the Policy')

    parser.add_argument('-exact', '--exact-match', action='store_true',
                         default=False, dest='exact_match',
                         help='Match the asset name exactly '
                              '(case-insensitive) instead of a '
                              'contains-match (default: no)')

    parser.add_argument('-dm', '--data_mover', required=False,
                         action='store', default="tsdm",
                         help='The VM data mover type - either TSDM or vADP')

    parser.add_argument('-storage_name', '--storage_name', required=False,
                         action='store', default=None,
                         help='The Data Domain name to use in the policy')

    parser.add_argument('-strgeid', '--storage_id', required=False,
                         action='store', default=None,
                         help='The Data Domain ID to use in the policy')

    parser.add_argument('-ddnic', '--datadomain_nic', required=False,
                         action='store', default="fqdn",
                         help='The Data Domain NIC to use in the policy')

    parser.add_argument('-freq', '--frequency', action='store',
                         choices=["hourly", "daily", "weekly", "monthly"],
                         help='Backup frequency')

    parser.add_argument('-i', '--interval', action='store', default=None,
                         help='Hourly interval')

    parser.add_argument('-stime', '--starttime', action='store',
                         default=None, help='Start Time (24hr)')

    parser.add_argument('-d', '--duration', action='store', default=None,
                         help='Duration in hours')

    parser.add_argument('-wkd', '--weekdays', required=False, action='store',
                         default=None, help='Week days')

    parser.add_argument('-dmon', '--daymonth', required=False,
                         action='store', default=None,
                         help='Comma-separated list of days in month')

    parser.add_argument('-ret', '--retention', action='store',
                         help='Retention in either day, week or month units')

    parser.add_argument('-force', '--force-reassign', action='store_true',
                         default=False, dest='force_reassign',
                         help='Allow reassigning an asset that already '
                              'belongs to another policy (default: no)')

    parser.add_argument('-existing', '--use-existing', action='store_true',
                         default=False, dest='use_existing',
                         help='If a policy with this name already '
                              'exists, add assets to it instead of '
                              'failing (default: no)')

    parser.add_argument('-tls', '--verify-cert', action='store_true',
                         default=False,
                         help='Enable TLS certificate verification using '
                              'system CAs')

    parser.add_argument('-log', '--log-file', action='store',
                         default='addpolicy.log',
                         help='Log file path (default: addpolicy.log)')

    args = parser.parse_args()

    return args


def setup_logger(log_file):
    """Configure logging to file only and log execution start"""
    max_bytes = 10 * 1024 * 1024
    log_backup_count = 5

    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=log_backup_count
        )
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - "
            "%(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        redacted_argv = list(sys.argv)
        for index, arg in enumerate(redacted_argv):
            if arg in ("-pwd", "--password") and index + 1 < len(
                    redacted_argv):
                redacted_argv[index + 1] = "*** REDACTED ***"
        logger.info("addpolicy started")
        logger.info("Command: %s", " ".join(redacted_argv))
    except (OSError, IOError) as error:
        print(f"-> Could not create log file: {error}")


def parse_version(version):
    """Parses the PPDM version string into a comparable float"""
    try:
        parts = version.split('-')[0].split('.')
        if len(parts) >= 2:
            return float(f"{parts[0]}.{parts[1]}")
        return float(parts[0])
    except (ValueError, IndexError):
        return 0.0


def sanitize_payload_for_logging(payload_str, uri):
    """Redacts credentials from a payload before it is logged"""
    if uri.endswith("/login") and payload_str:
        return "*** REDACTED ***"

    return payload_str


def init_rest_call(verb, uri, token, payload=None, params=None, verify=False):
    """Generic function for REST calls"""
    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " f"{token}",
        }
    payload_str = json.dumps(payload)
    timeout = 90

    logger.info(
        "REST Call: %s %s, Params: %s, Payload: %s", verb, uri, params,
        sanitize_payload_for_logging(payload_str, uri)
    )

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
                data=payload_str,
                verify=verify,
                timeout=timeout,
            )
        response.raise_for_status()
    except requests.exceptions.ConnectionError as error:
        print(f"-> Error Connecting to {uri}: {error}")
        logger.error("Connection error: %s - %s", uri, error)
        raise SystemExit(1) from error
    except requests.exceptions.Timeout as error:
        print(f"-> Connection timed out {uri}: {error}")
        logger.error("Connection timed out: %s - %s", uri, error)
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if response.status_code in (401, 502):
            logger.error(
                "REST call failed: %s %s - Status %d", verb, uri,
                response.status_code
            )
            return False
        print(
            f"-> The call {response.request.method} {response.url} \
                failed with exception:{error}"
        )
        logger.error(
            "REST call failed: %s %s - Status %d - Exception: %s",
            response.request.method, response.url,
            response.status_code, error
        )
        return False

    logger.info(
        "REST call successful: %s %s, status: %d, time: %.3fs", verb, uri,
        response.status_code, response.elapsed.total_seconds()
    )

    if not response.content:
        return True
    if uri.endswith("/login"):
        return response.json()["access_token"]

    try:
        return response.json()
    except (AttributeError, ValueError):
        return response.content


def authenticate(uri, user, password, verify=False):
    """Logins into PowerProtect Data Manager"""
    uri = f"{uri}/login"
    payload = {"username": user, "password": password}
    token = init_rest_call("POST", uri, payload, payload, verify=verify)

    if not token:
        print(f"Login failed for user: {user}. Exiting...")
        logger.error("Login failed for user: %s", user)
        raise SystemExit(1)

    logger.info("Login succeeded for user: %s", user)

    return token


def get_version(uri, token, verify=False):
    """Gets the PPDM version"""
    uri = f"{uri}/nodes"
    response = init_rest_call("GET", uri, token, verify=verify)

    if not isinstance(response, dict) or not response.get("content"):
        print("Could not determine PPDM version. Exiting...")
        logger.error("Could not determine PPDM version")
        raise SystemExit(1)

    if "version" in response["content"][0]:
        version = response["content"][0]["version"]
        logger.info("PPDM version detected: %s", version)
        return version

    print("Could not determine PPDM version. Exiting...")
    logger.error("Could not determine PPDM version")
    raise SystemExit(1)


def get_policy(uri, token, verify=False):
    """Get configured protection policies"""
    uri = f"{uri}/protection-policies"
    response = init_rest_call("GET", uri, token, verify=verify)

    return response["content"]


def find_policy(policies, name):
    """Finds a policy by name and returns it, or None if not found"""
    for policy in policies:
        if name == policy["name"]:
            return policy

    return None


def find_policy_name(policies, policy_id):
    """Finds a policy's name by ID, falling back to the ID itself"""
    for policy in policies:
        if policy["id"] == policy_id:
            return policy["name"]

    return policy_id


def get_asset(uri, token, name, asset_id, asset_type, verify=False,
               exact_match=False):
    """Gets assets by name or ID, regardless of protection status"""
    uri = f"{uri}/assets"
    query = f'type eq "{asset_type}"'

    if asset_id is not None:
        query += f' and id eq "{asset_id}"'

    if name is not None:
        name = name.replace('*', '')
        query += f' and name lk "%{name}%"'
    query_params = {'filter': query}

    response = init_rest_call(
        "GET", uri, token, False, query_params, verify=verify
    )
    asset_data = response["content"]

    if exact_match and name is not None:
        exact_matches = []
        for spec_asset in asset_data:
            if spec_asset["name"].lower() == name.lower():
                exact_matches.append(spec_asset)
        return exact_matches

    return asset_data


def get_storage(uri, token, storage_name, storage_id, verify=False):
    """Get Data Domain storage systems"""
    uri = f"{uri}/storage-systems"
    query = 'type eq "DATA_DOMAIN_SYSTEM"'

    if storage_id is not None:
        query += f' and id lk "%{storage_id}%"'

    if storage_name is not None:
        query += f' and name lk "%{storage_name}%"'

    query_params = {'filter': query}

    response = init_rest_call(
        "GET", uri, token, False, query_params, verify=verify
    )

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


def parse_hourly_interval(interval):
    """Validates and converts the hourly interval to an integer"""
    number = str(interval).split()[0]

    if not number.isdigit():
        print("Please specify the hourly interval in full hours")
        print("For example: 4 or '4 hours'")
        raise SystemExit(5)

    interval = int(number)
    if not 1 <= interval <= 23:
        print("Please specify an hourly interval between 1 and 23")
        raise SystemExit(5)

    return interval


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
        schedule["interval"] = parse_hourly_interval(interval)
    elif freq == "weekly":
        schedule["weekDays"] = str(weekdays).upper()
    elif freq == "monthly":
        schedule["dayOfMonth"] = daymonth

    return schedule


def build_schedule_v3(freq, starttime, interval, duration, weekdays,
                       daymonth):
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
        schedule["recurrence"]["pattern"]["interval"] = (
            parse_hourly_interval(interval)
        )
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


def build_policy_json(name, schedule, retention, storage, asset_type,
                       data_mover):
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


def build_policy_json_v3(name, schedule, retention, storage, asset_type,
                          data_mover):
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


def create_policy(uri, token, policy_data, verify=False):
    """Creates policy based on the policy JSON"""
    uri = f"{uri}/protection-policies"
    response = init_rest_call("POST", uri, token, policy_data, verify=verify)

    if isinstance(response, dict) and "id" in response:
        logger.info(
            "Policy created: %s (%s)", response["id"], policy_data["name"]
        )
        return response["id"]

    print("Could not create policy. Exiting...")
    logger.error("Could not create policy")
    raise SystemExit(1)


def assign_asset(uri, token, asset_id, policy_id, verify=False,
                  policy_name=None, asset_names=None):
    """Assigns an asset to a policy"""
    uri = f"{uri}/protection-policies/{policy_id}/asset-assignments"
    response = init_rest_call("POST", uri, token, asset_id, verify=verify)

    logger.info(
        "Asset assignment: assets %s (%s) -> policy %s (%s): %s",
        asset_id, asset_names, policy_id, policy_name, response
    )

    return response


def main():
    """Parses args, authenticates, and runs the requested action"""
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_release = 19.16
    api_v3_endpoint = "/api/v3"
    api_v3 = False

    # Parse args and resolve TLS verification
    args = get_args()
    setup_logger(args.log_file)
    verify = args.verify_cert
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Resolve password from the environment or the command line
    if args.envpassword:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            print("PPDM_PASSWORD environment variable not set. Exiting...")
            logger.error("PPDM_PASSWORD environment variable not set")
            raise SystemExit(1)
    elif args.password:
        password = args.password
    else:
        print("Password is required. Use -pwd or -envpassword. Exiting...")
        logger.error("Password not provided")
        raise SystemExit(1)

    ppdm, user = args.server, args.user
    action, name = args.action, args.name
    asset, asset_id, asset_type = args.asset, args.id, args.type
    exact_match = args.exact_match
    storage_name, storage_id = args.storage_name, args.storage_id
    dd_nic = args.datadomain_nic
    freq, starttime, interval = args.frequency, args.starttime, args.interval
    duration, weekdays, daymonth = args.duration, args.weekdays, args.daymonth
    retention = args.retention
    data_mover = args.data_mover
    force_reassign = args.force_reassign
    use_existing = args.use_existing

    # Authenticate
    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(uri, user, password, verify)
    version = get_version(uri, token, verify)

    if parse_version(version) > api_v3_release:
        print("Using The PowerProtect Data Manager v3 API")
        api_v3 = True
        uri_v3 = f"https://{ppdm}:{api_port}{api_v3_endpoint}"
        policies = get_policy(uri_v3, token, verify)
    else:
        policies = get_policy(uri, token, verify)

    # Action: list
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
                    print("Number of Assets:",
                          policy["summary"]["numberOfAssets"])
                    print("Number of Stages:", len(policy["stages"]))
                print()
        return

    # Action: create
    if name is None:
        print("Please specify a policy name")
        raise SystemExit(1)

    asset_type = asset_type.lower()
    data_mover = data_mover.lower()
    no_asset = False
    if asset is None and asset_id is None:
        print("Creating a policy without any assets")
        no_asset = True

    asset_type_map = {
        "vm": "VMWARE_VIRTUAL_MACHINE",
        "hyperv": "HYPERV_VIRTUAL_MACHINE",
        "nutanix": "NUTANIX_VIRTUAL_MACHINE",
        "nativeedge": "NATIVEEDGE_VIRTUAL_MACHINE",
        "k8s": "KUBERNETES",
    }
    if asset_type not in asset_type_map:
        print("Defaulting to VMware VM asset type")
        asset_type = "VMWARE_VIRTUAL_MACHINE"
    else:
        asset_type = asset_type_map[asset_type]

    # Data mover selection only applies to VMware VM policies
    if asset_type == "VMWARE_VIRTUAL_MACHINE":
        if data_mover.lower() not in ("tsdm", "vadp"):
            data_mover = "SDM"
        elif data_mover == "tsdm":
            data_mover = "SDM"
        elif data_mover == "vadp":
            data_mover = "VADP"

    existing_policy = find_policy(policies, name)
    if existing_policy and not use_existing:
        print(f"Policy {name} already exists.")
        print("Rerun with -existing to add assets to it instead, "
              "or pick a different name")
        raise SystemExit(5)

    # Resolve and validate assets before creating a new policy
    asset_list = []
    asset_names = []
    if not no_asset:
        assets = asset.split(',')
        for asset in assets:
            asset = asset.strip()
            has_wildcard = "*" in asset
            asset_data = get_asset(uri, token, asset, asset_id, asset_type,
                                    verify, exact_match)
            if len(asset_data) == 0:
                print(f"Asset {asset} could not be found")
                continue

            if len(asset_data) > 1 and not has_wildcard:
                matched_names = []
                for spec_asset in asset_data:
                    matched_names.append(spec_asset["name"])
                print(f"Asset name '{asset}' matched more than one "
                      f"asset: {', '.join(matched_names)}")
                print("Use '*' to intentionally assign multiple "
                      "matching assets, or -exact to match this name "
                      "exactly. Skipping this entry")
                continue

            for spec_asset in asset_data:
                existing_policy_id = spec_asset.get("protectionPolicyId")
                if existing_policy_id and not force_reassign:
                    existing_policy_name = find_policy_name(
                        policies, existing_policy_id
                    )
                    print(f"Asset {spec_asset['name']} already belongs "
                          f"to policy {existing_policy_name}.")
                    print("Use -force to reassign it. Exiting...")
                    raise SystemExit(1)
                if spec_asset["status"] != "AVAILABLE":
                    print(f"Asset {spec_asset['name']} could not be "
                          "added:", end=' ')
                    print(f"asset status is {spec_asset['status']}")
                else:
                    if existing_policy_id:
                        reassigned_from = find_policy_name(
                            policies, existing_policy_id
                        )
                        print(f"Asset {spec_asset['name']} is being "
                              f"reassigned from policy {reassigned_from}")
                    asset_list.append(spec_asset["id"])
                    asset_names.append(spec_asset["name"])
                    print(f"Assigning asset: {spec_asset['name']} to "
                          f"policy: {name}")

        if not asset_list:
            print("No assets could be resolved for assignment. "
                  "Exiting without creating a policy...")
            raise SystemExit(1)

    if existing_policy:
        policy_id = existing_policy["id"]
        print(f"Using existing policy: {name}")
    else:
        if storage_name is None and storage_id is None:
            print("Please specify either storage name or ID")
            raise SystemExit(1)
        if None in [starttime, duration, retention]:
            print("Make sure that starttime, duration and retention "
                  "parameters are set")
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

        storage_list = get_storage(uri, token, storage_name, storage_id,
                                    verify)
        if len(storage_list) > 1:
            print(f"Storage Name {storage_name} yielded in more than "
                  "1 result")
            print("Narrow down the results using the --storage_name "
                  "and --storage_id parameters")
            raise SystemExit(5)
        storage = extract_datadomain_nic(storage_list, dd_nic)

        if api_v3:
            schedule = build_schedule_v3(freq, starttime, interval,
                                          duration, weekdays, daymonth)
            retention = build_retention(retention)
            policy_data = build_policy_json_v3(name, schedule, retention,
                                                storage, asset_type,
                                                data_mover)
            policy_id = create_policy(uri_v3, token, policy_data, verify)
        else:
            schedule = build_schedule(freq, starttime, interval, duration,
                                       weekdays, daymonth)
            retention = build_retention(retention, True)
            policy_data = build_policy_json(name, schedule, retention,
                                             storage, asset_type,
                                             data_mover)
            policy_id = create_policy(uri, token, policy_data, verify)
        print(f"Policy: {name} created successfully")

    # Assign assets
    if no_asset:
        print("Skipping asset assignment")
        return

    if assign_asset(uri, token, asset_list, policy_id, verify,
                     policy_name=name, asset_names=asset_names):
        print(f"All assets successfully assigned to policy: {name}")
    else:
        print(f"Failed to assign assets to policy: {name}")


if __name__ == "__main__":
    main()
