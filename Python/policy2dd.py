#!/usr/bin/env python3

import json
import argparse
import requests
import urllib3

# The purpose of this script is to report on Policy to Data Domain info
# Examples:
# python policy2dd.py -s 10.0.0.1 -usr admin -pwd "myPassword!"
# python policy2dd.py -s 10.0.0.1 pwd "myPassword!" -n prod_policy


urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script to show Policy to Data Domain information in PPDM')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-n', '--name', required=False, default=None,
                        help='Optionally specify policy to query')
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


def get_policy(uri, token, policy_name):
    """Get configured protection policies"""
    query_params = None
    if "/api/v3" in uri:
        uri = f"{uri}/policies"
    else:
        uri = f"{uri}/protection-policies"
    if policy_name is not None:
        query = f'name eq "{policy_name}"'
        query_params = {'filter': query}
    response = init_rest_call("GET", uri, token, None, query_params)
    if "content" not in response or len(response["content"]) == 0:
        return False
    return response["content"]


def get_storage_info(policy):
    """Get Data Domain storage info"""
    policy.setdefault("dpType", [])
    policy.setdefault("ddId", [])
    policy.setdefault("suId", [])
    policy.setdefault("ddNic", [])
    for stage in policy["stages"]:
        if stage["type"] == "PROTECTION":
            stage["type"] = "BACKUP"
        policy["dpType"].append(stage["type"])
        policy["ddId"].append(stage["target"]["storageContainerId"])
        policy["suId"].append(stage["target"]["storageTargetId"])
        policy["ddNic"].append(stage["target"]["preferredInterfaceId"])
    return policy


def get_storage_info_v3(policy):
    """Get Data Domain storage info for API v3"""
    policy.setdefault("dpType", [])
    policy.setdefault("ddId", [])
    policy.setdefault("suId", [])
    policy.setdefault("ddNic", [])
    for objective in policy["objectives"]:
        policy["dpType"].append(objective["type"])
        policy["ddId"].append(objective["target"]["storageContainerId"])
        policy["suId"].append(objective["target"]["storageTargetId"])
        policy["ddNic"].append(objective["target"]["preferredInterfaceId"])
    return policy


def get_dd_name(uri, token, policy):
    """Get Data Domain storage name by ID"""
    uri = f"{uri}/storage-systems"
    policy.setdefault("ddName", [])
    for counter in range(len(policy["dpType"])):
        query = 'type eq "DATA_DOMAIN_SYSTEM"'
        query += f' and id eq "{policy["ddId"][counter]}"'
        query_params = {'filter': query}
        response = init_rest_call("GET", uri, token, False, query_params)
        if "content" in response:
            if len(response["content"]) == 1:
                policy["ddName"].append(response["content"][0]["name"])
        else:
            policy["ddName"][counter] = False
    return policy


def get_dd_storageunit(uri, token, policy):
    "Gets Storage Unit name by ID"
    uri = f"{uri}/datadomain-mtrees"
    policy.setdefault("suName", [])
    for counter in range(len(policy["dpType"])):
        query = f'storageSystem.id eq "{policy["ddId"][counter]}"'
        query += f' and id eq "{policy["suId"][counter]}"'
        query += ' and type eq "DDSTORAGEUNIT"'
        query_params = {'filter': query}
        response = init_rest_call("GET", uri, token, None, query_params)
        if "content" not in response:
            return False
        policy["suName"].append(response["content"][0]["name"])
    return policy


def main():
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_release = 19.16
    api_v3_endpoint = "/api/v3"
    api_v3 = False

    args = get_args()
    ppdm, user, password = args.server, args.user, args.password
    policy_name = args.name

    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(uri, user, password)
    version = get_version(uri, token)

    if float(version[:5]) > api_v3_release:
        print("Using The PowerProtect Data Manager v3 API")
        api_v3 = True
        uri_v3 = f"https://{ppdm}:{api_port}{api_v3_endpoint}"
        policies = get_policy(uri_v3, token, policy_name)
    else:
        policies = get_policy(uri, token, policy_name)
    if not policies:
        if policy_name is not None:
            print("Policy could not be found. Exiting...")
            raise SystemExit(5)
        print("No policies found. Exiting...")
        raise SystemExit(5)
    for policy in policies:
        print("------------------------------------------------------")
        print("Policy Name:", policy["name"])
        print("Policy ID:", policy["id"])
        print("Policy Type:", policy["assetType"])
        if api_v3:
            print("Policy Disabled:", policy["disabled"])
            policy = get_storage_info_v3(policy)
        else:
            print("Policy Enabled:", policy["enabled"])
            policy = get_storage_info(policy)
        policy = get_dd_name(uri, token, policy)
        if False in policy["ddName"]:
            print("Could not retrieve Data Domain Info")
        policy = get_dd_storageunit(uri, token, policy)
        if not policy["suName"]:
            print("Could not retrieve Storage Unit Info")
        if len(policy["dpType"]) == 1:
            policy["dpType"] = policy["dpType"][0]
            policy["ddName"] = policy["ddName"][0]
            policy["suName"] = policy["suId"][0]
            policy["ddNic"] = policy["ddNic"][0]
        print("Data Protection Operation:", policy["dpType"])
        print("Data Domain Name:", policy["ddName"])
        print("Data Domain SU Name:", policy["suName"])
        print("Data Domain NIC:", policy["ddNic"])
        print()


if __name__ == "__main__":
    main()
