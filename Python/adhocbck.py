#!/usr/bin/env python3

import argparse
import sys
import json
import time
import requests
import urllib3

# This script facilitates ad-hoc backups in PowerProtect Data Manager
# Author - Idan Kentor <idan.kentor@dell.com>
# Copyright [2025] [Idan Kentor]

# Examples:
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n VM1
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n VM2 -t hyperv_vm
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n VM3 -ret "1 days" -full
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list -t k8s
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n k8s-ns1 -t k8s
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a list -t pmax
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a backup -n sg1 -t pmax -ret "2 months" -nmonitor
# python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -a monitor -activity_id 4e78e92f-6233-4210-93ee-a94458fd87d1


urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script for ad-hoc backups in PowerProtect Data Manager')

    parser.add_argument("-s", "--server",
                        required=True,
                        help="PPDM DNS name or IP")
    parser.add_argument("-usr", "--user",
                        default="admin",
                        help="Username (default: admin)")
    parser.add_argument("-pwd", "--password",
                        required=True,
                        help="Password for authentication")
    parser.add_argument("-a", "--action",
                        required=True,
                        choices=["list", "backup", "monitor", "list-raw"],
                        help="List assets or perform ad-hoc backup")
    parser.add_argument("-n", "--name",
                        required=("backup" in sys.argv and "-id" not in sys.argv),
                        default=None,
                        help="Name of the asset to backup")
    parser.add_argument(
        "-t", "--type",
        default="vmw_vm",
        choices=[
            "vmw_vm", "hyperv_vm", "nutanix_vm", "nativeedge_vm",
            "pmax", "pstore", "k8s"],
        help=(
            "Asset type (default: vmw_vm). Choices: "
            "vmw_vm=VMWARE VM, "
            "hyperv_vm=HYPERV VM, "
            "nutanix_vm=NUTANIX VM, "
            "nativeedge_vm=Dell NativeEdge VM, "
            "pmax=POWERMAX STORAGE GROUP, "
            "pstore=POWERSTORE VOLUME GROUP, "
            "k8s=KUBERNETES NAMESPACE"))
    parser.add_argument("-id", "--id",
                        required=("backup" in sys.argv and "-n" not in sys.argv),
                        default=None,
                        help="Asset ID to backup")
    parser.add_argument("-activity_id", "--activity_id",
                        required=("monitor" in sys.argv and "-aidfile" not in sys.argv),
                        help="Activity ID to monitor")
    parser.add_argument("-full", "--full",
                        action="store_true",
                        default=False,
                        help="Force full backup")
    parser.add_argument("-ret", "--retention",
                        help="Retention period (e.g., days, weeks, or months)")
    parser.add_argument("-nmonitor", "--no-monitor",
                        action="store_true",
                        dest="nmonitor",
                        default=False,
                        help="Skip backup monitoring")
    parser.add_argument("-aidfile", "--activity-id-file",
                        required=("monitor" in sys.argv and "-activity_id" not in sys.argv),
                        dest="aidfile",
                        default=None,
                        help="File to retrieve the activity ID from")
    parser.add_argument("-outfile", "--output-file",
                        action="store",
                        dest="outfile",
                        default=None,
                        help="File to save asset and activity ID")

    args = parser.parse_args()
    return args


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""

    headers = {"Content-Type": "application/json"}
    if not uri.endswith("/login") and token:
        headers["Authorization"] = f"Bearer {token}"

    verify = False
    timeout = 90

    verb = verb.lower()
    payload = json.dumps(payload)

    try:
        if verb == "get":
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
        print(f"-> Connection timed out {uri}: {error}")
        raise SystemExit(1) from error
    except requests.exceptions.RequestException as error:
        if not response or response.status_code in (401, 502):
            return False
        print(
            f"-> The call {response.request.method} {response.url} \
                failed with exception:{error}"
        )

    if not response.content:
        return True

    if uri.endswith("/login"):
        try:
            return response.json()["access_token"]
        except (ValueError, KeyError) as error:
            print("-> Login failed. Exiting")
            raise SystemExit(1) from error

    try:
        return response.json()
    except (AttributeError, ValueError):
        return response.content


def authenticate(ppdm, user, password, uri):
    """PPDM login"""
    uri = f"{uri}/login"
    login_payload = {"username": user, "password": password}

    token = init_rest_call("POST", uri, login_payload, login_payload)

    if token:
        print(f"Login for user: {user} to PPDM: {ppdm} succeeded")
        return token

    print(f"Cannot login to PPDM {ppdm}")
    raise SystemExit(1)


def get_version(uri, token):
    """Gets the PPDM version"""
    uri = f"{uri}/nodes"

    response = init_rest_call("GET", uri, token)

    if not isinstance(response, dict) or "content" not in response:
        raise SystemExit("Cannot check PPDM version.")

    if not isinstance(response["content"], list) or not response["content"]:
        raise SystemExit("Cannot check PPDM version.")

    if "version" in response["content"][0]:
        return response["content"][0]["version"]

    print("Could not determine PPDM version.")
    raise SystemExit(1)


def get_asset(uri, token, name, asset_type, asset_id):
    """Gets asset by type or ID"""
    uri = f"{uri}/assets"

    asset_type_filters = {
        "vmw_vm": 'type eq "VMWARE_VIRTUAL_MACHINE"',
        "hyperv_vm": 'type eq "HYPERV_VIRTUAL_MACHINE"',
        "nutanix_vm": 'type eq "NUTANIX_VIRTUAL_MACHINE"',
        "nativeedge_vm": 'type eq "NATIVEEDGE_VIRTUAL_MACHINE"',
        "k8s": 'type eq "KUBERNETES" and subtype eq "K8S_NAMESPACE"',
        "pmax": (
            'type eq "POWER_MAX_BLOCK" and '
            'subtype eq "POWER_MAX_STORAGE_GROUP"'
        ),
        "pstore": (
            'type eq "POWERSTORE_BLOCK" and '
            'subtype eq "POWERSTORE_VOLUME_GROUP"'
        )
    }
    query = asset_type_filters[asset_type]

    if asset_id is not None:
        query += f' and id eq "{asset_id}"'

    if name is not None:
        query += f' and name lk "{name}"'

    params = {"filter": query}

    response = init_rest_call("GET", uri, token, None, params)
    return response.get("content")


def extract_stage_id(uri, token, policy_id):
    """Finds the protection stage ID of a given protection policy"""
    uri = f"{uri}/protection-policies/{policy_id}"

    response = init_rest_call("GET", uri, token)

    if not isinstance(response, dict):
        print("Could not retrieve protection policy stages")
        raise SystemExit(1)

    if "stages" in response:
        for stage in response["stages"]:
            if stage.get("type") == "PROTECTION":
                return stage.get("id")

    print("Could not retrieve the protection stage in the proteciton policy")
    raise SystemExit(1)


def extract_stage_id_v3(uri, token, policy_id):
    """Finds the protection stage ID of a given protection policy - v3 API"""
    uri = f"{uri}/protection-policies/{policy_id}"

    response = init_rest_call("GET", uri, token)

    if not isinstance(response, dict):
        print("Could not retrieve protection policy stages")
        raise SystemExit(1)

    if "objectives" in response:
        for objective in response["objectives"]:
            if objective.get("type") == "BACKUP":
                return objective.get("id")

    print("Could not retrieve the backup stage in the proteciton policy")
    raise SystemExit(1)


def build_retention(retention, api_v3=None):
    """Builds the retention JSON for both API versions"""
    error_msg = (
        "Specify retention in the format of 'number UNIT'\n"
        "For example: 5 days")

    ret_lock = False
    ret_list = str(retention).strip().split()

    if len(ret_list) != 2 or not ret_list[0].isdigit():
        print(error_msg)
        raise SystemExit(2)

    number_str, unit_raw = ret_list

    try:
        interval = int(number_str)
    except ValueError as error:
        print("Retention number must be an integer (e.g., '5 days')")
        raise SystemExit(2) from error

    if interval <= 0:
        print("Retention number must be a positive integer")
        raise SystemExit(2)

    unit_norm = unit_raw.strip().lower()
    unit_map = {
        "day": "DAY", "days": "DAY",
        "week": "WEEK", "weeks": "WEEK",
        "month": "MONTH", "months": "MONTH",
    }
    if unit_norm not in unit_map:
        print("Invalid unit. Allowed units: day(s), week(s), month(s).")
        raise SystemExit(2)

    if api_v3:
        timej = [{}]
        timej[0]["type"] = "RETENTION"
        timej[0]["unitValue"] = interval
        timej[0]["unitType"] = unit_map[unit_norm]
        retentionj = [{"time": timej}]
        return retentionj

    retentionj = {}
    retentionj["interval"] = interval
    retentionj["unit"] = unit_map[unit_norm]
    retentionj["storageSystemRetentionLock"] = ret_lock
    return retentionj


def build_protection_payload(asset_id, stage_id, retention, backup_type):
    """Builds the required payload for the adhoc protection call"""
    stage = {"id": stage_id, "operation": {}}

    if retention:
        stage["retention"] = build_retention(retention)

    stage["operation"]["backupType"] = "FULL" if backup_type else "SYNTHETIC_FULL"

    return {"assetIds": [asset_id], "stages": [stage]}


def build_protection_payload_v3(asset_id, policy_id, stage_id, retention, backup_type):
    """Builds the required payload for the adhoc protection call - v3 API"""
    objective = {
        "id": stage_id,
        "operation": {
            "backupLevel": "FULL" if backup_type else "SYNTHETIC_FULL"
        }
    }

    if retention:
        objective["retentions"] = build_retention(retention, True)

    protect_payload = {
        "source": {"assetIds": [asset_id]},
        "policy": {
            "id": policy_id,
            "objectives": [objective],
        }
    }

    return protect_payload


def adhoc_backup(uri, token, policy_id, protect_payload):
    """Performs ad-hoc backup of a VM by name or ID"""
    uri = f"{uri}/protection-policies/{policy_id}/protections"

    response = init_rest_call("POST", uri, token, protect_payload)

    try:
        return response.json()["results"][0]["activityId"]
    except (KeyError, AttributeError, ValueError, IndexError) as error:
        print("Ad-hoc protection call failed")
        raise SystemExit(1) from error


def adhoc_backup_v3(uri, token, protect_payload):
    """Performs ad-hoc backup of a VM by name or ID - API v3"""
    uri = f"{uri}/protections"

    response = init_rest_call("POST", uri, token, protect_payload)

    try:
        return response["results"][0]["activityId"]
    except (KeyError, AttributeError, ValueError, IndexError) as error:
        print("Ad-hoc protection call failed")
        raise SystemExit(1) from error


def monitor_activity(uri, token, activity_id):
    """Monitors an activity by its ID"""
    timeout = 1200  # 20 minutes timeout
    interval = 10  # 10 seconds interval

    uri = f"{uri}/activities/{str(activity_id)}"
    start = time.monotonic()

    while True:
        if (time.monotonic() - start) > timeout:
            return "TIMEOUT"
        try:
            response = init_rest_call("GET", uri, token)
        except (ConnectionError, TimeoutError):
            timestamp = time.strftime("%m-%d-%y %H:%M:%S")
            print(f"Activity {activity_id} POLL_ERROR at {timestamp}")
            time.sleep(interval)
            continue
        state = response.get("state")
        timestamp = time.strftime("%m-%d-%y %H:%M:%S")
        print(f"Activity {activity_id} {state} at {timestamp}")
        if state == "COMPLETED":
            duration_ms = response.get("duration", 0)
            duration_sec = duration_ms / 1000.0
            minutes, seconds = divmod(duration_sec, 60.0)
            print(f"Backup completed in {int(minutes)} minutes and {round(seconds, 2)} seconds")
            result = response.get("result", {})
            status = result.get("status", "UNKNOWN")
            return status
        time.sleep(interval)


def main():
    # Const definition
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_release = 19.16
    api_v3_endpoint = "/api/v3"
    api_v3 = False
    uri_v3 = None

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
                    aid = file_handle.read().strip()
                except OSError as error:
                    print("Could not get activity ID from file")
                    raise SystemExit(1) from error
        monitor_activity(uri, token, aid)
        raise SystemExit(0)

    assets = get_asset(uri, token, name, asset_type, asset_id)
    if not assets:
        print("Asset could not be found")
        raise SystemExit(1)

    if action == "list":
        for asset in assets:
            print("------------------------------------------------------")
            print("Asset ID:", asset.get("id"))
            print("Asset Name:", asset.get("name"))
            print("Asset Type:", asset.get("type"))
            last_bck = asset.get("lastAvailableCopyTime")
            if last_bck:
                time_obj = time.strptime(last_bck, "%Y-%m-%dT%H:%M:%SZ")
                last_bck = time.strftime("%m/%d/%y %I:%M:%S %p", time_obj) + " UTC"
            print("Last Backup Time:", last_bck)
            print()
        raise SystemExit(0)

    if action == "list-raw":
        print("JSON output for asset:", name or asset_id)
        print(json.dumps(assets, indent=4))
        raise SystemExit(0)

    if len(assets) > 1:
        print(f"Asset name {name} yielded in more than a single result")
        print("Narrow down the results using the --id or --type parameters")
        raise SystemExit(2)

    asset = assets[0]
    timestamp = time.strftime("%m-%d-%y %H:%M:%S")
    print(f"Performing Ad-hoc backup for asset {asset.get('name')} at {timestamp}")
    policy_id = asset.get("protectionPolicyId")
    asset_id = asset.get("id")

    if api_v3:
        print("Using PowerProtect Data Manager v3 API")
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
                except OSError as error:
                    print("Could not log activity ID to file")
                    raise SystemExit(1) from error
            print("Activity ID logged to file:", outfile)


if __name__ == "__main__":
    main()

