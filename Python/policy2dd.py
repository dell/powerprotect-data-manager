#!/usr/bin/env python3

import argparse
import json
import os
import requests
import urllib3

# The purpose of this script is to report on Policy to Data Domain info
# Author - Idan Kentor <idan.kentor@dell.com>
# Copyright [2026] [Idan Kentor]

# Examples:
# python policy2dd.py -s 10.0.0.1 -usr admin -pwd "myPassword!"
# python policy2dd.py -s 10.0.0.1 -usr admin -envpassword
# python policy2dd.py -s 10.0.0.1 -usr admin -pwd "myPassword!" -n prod_policy
# python policy2dd.py -s 10.0.0.1 -usr admin -envpassword -o json
# python policy2dd.py -s 10.0.0.1 -usr admin -envpassword -o json -f report.json

urllib3.disable_warnings()


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(
        description='Script to show Policy to Data Domain information in PPDM')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=False, action='store',
                        help='Password')
    parser.add_argument('-envpassword', '--env-password', required=False,
                        action='store_true', dest='envpassword',
                        help='Read password from PPDM_PASSWORD environment variable')
    parser.add_argument('-n', '--name', required=False, default=None,
                        help='Optionally specify policy to query')
    parser.add_argument('-o', '--output', required=False, default='text',
                        choices=['text', 'json', 'yaml', 'csv'],
                        help='Output format (default: text)')
    parser.add_argument('-f', '--file', required=False, default=None,
                        help='Output file path (default: stdout)')
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


def parse_version(version):
    """Parse version string to float"""
    try:
        parts = version.split('-')[0].split('.')
        if len(parts) >= 2:
            return float(f"{parts[0]}.{parts[1]}")
        return float(parts[0])
    except (ValueError, IndexError):
        return 0.0


def get_policy(uri, token, policy_name):
    """Get configured protection policies"""
    uri = f"{uri}/protection-policies"
    query_params = None

    if policy_name is not None:
        query = f'name eq "{policy_name}"'
        query_params = {'filter': query}

    response = init_rest_call("GET", uri, token, None, query_params)

    if not isinstance(response, dict):
        return []

    if "content" not in response or len(response["content"]) == 0:
        return []

    return response["content"]


def get_storage_info(policy, api_v3):
    """Get Data Domain storage info"""
    policy["dpType"] = []
    policy["ddId"] = []
    policy["suId"] = []
    policy["ddNic"] = []

    if api_v3:
        objectives = policy.get("objectives")
        if not objectives:
            return policy
        for objective in objectives:
            target = objective.get("target") or {}
            policy["dpType"].append(objective.get("type", ""))
            policy["ddId"].append(target.get("storageContainerId", ""))
            policy["suId"].append(target.get("storageTargetId", ""))
            policy["ddNic"].append(target.get("preferredInterfaceId", ""))
    else:
        for stage in policy.get("stages", []):
            stage_type = stage.get("type", "")
            if stage_type == "PROTECTION":
                stage_type = "BACKUP"
            target = stage.get("target") or {}
            policy["dpType"].append(stage_type)
            policy["ddId"].append(target.get("storageContainerId", ""))
            policy["suId"].append(target.get("storageTargetId", ""))
            policy["ddNic"].append(target.get("preferredInterfaceId", ""))

    return policy


def get_dd_name(uri, token, policy):
    """Get Data Domain storage name by ID"""
    uri = f"{uri}/storage-systems"
    policy["ddName"] = []

    for counter in range(len(policy["dpType"])):
        query = 'type eq "DATA_DOMAIN_SYSTEM"'
        query += f' and id eq "{policy["ddId"][counter]}"'
        query_params = {'filter': query}
        response = init_rest_call("GET", uri, token, False, query_params)

        if isinstance(response, dict) and "content" in response:
            if len(response["content"]) == 1:
                policy["ddName"].append(response["content"][0]["name"])
            else:
                policy["ddName"].append("Unknown")
        else:
            policy["ddName"].append("Unknown")

    return policy


def get_dd_storageunit(uri, token, policy):
    """Gets Storage Unit name by ID"""
    uri = f"{uri}/datadomain-mtrees"
    policy["suName"] = []

    for counter in range(len(policy["dpType"])):
        query = f'storageSystem.id eq "{policy["ddId"][counter]}"'
        query += f' and id eq "{policy["suId"][counter]}"'
        query += ' and type eq "DDSTORAGEUNIT"'
        query_params = {'filter': query}
        response = init_rest_call("GET", uri, token, None, query_params)

        if isinstance(response, dict) and "content" in response:
            if len(response["content"]) > 0:
                policy["suName"].append(response["content"][0]["name"])
            else:
                policy["suName"].append("Unknown")
        else:
            policy["suName"].append("Unknown")

    return policy


def format_text_output(policies, api_v3):
    """Format policies as text output"""
    output = []
    for policy in policies:
        output.append("------------------------------------------------------")
        output.append(f"Policy Name: {policy.get('name', 'N/A')}")
        output.append(f"Policy ID: {policy.get('id', 'N/A')}")
        output.append(f"Policy Type: {policy.get('assetType', 'N/A')}")

        if api_v3:
            output.append(f"Policy Disabled: {policy.get('disabled', False)}")
        else:
            output.append(f"Policy Enabled: {policy.get('enabled', True)}")

        dp_types = policy.get("dpType", [])
        dd_names = policy.get("ddName", [])
        su_names = policy.get("suName", [])
        dd_nics = policy.get("ddNic", [])

        if len(dp_types) == 0:
            pass
        elif len(dp_types) == 1:
            output.append(f"Data Protection Operation: {dp_types[0]}")
            output.append(f"Data Domain Name: {dd_names[0] if dd_names else 'N/A'}")
            output.append(f"Data Domain SU Name: {su_names[0] if su_names else 'N/A'}")
            output.append(f"Data Domain NIC: {dd_nics[0] if dd_nics else 'N/A'}")
        else:
            for idx in range(len(dp_types)):
                output.append(f"Stage {idx + 1}:")
                output.append(f"  Data Protection Operation: {dp_types[idx]}")
                output.append(f"  Data Domain Name: {dd_names[idx] if idx < len(dd_names) else 'N/A'}")
                output.append(f"  Data Domain SU Name: {su_names[idx] if idx < len(su_names) else 'N/A'}")
                output.append(f"  Data Domain NIC: {dd_nics[idx] if idx < len(dd_nics) else 'N/A'}")

        output.append("")

    return "\n".join(output)


def format_json_output(policies):
    """Format policies as JSON output"""
    result = {"policies": []}

    for policy in policies:
        policy_data = {
            "name": policy.get("name"),
            "id": policy.get("id"),
            "assetType": policy.get("assetType"),
            "enabled": policy.get("enabled", not policy.get("disabled", False)),
            "stages": []
        }

        dp_types = policy.get("dpType", [])
        dd_names = policy.get("ddName", [])
        su_names = policy.get("suName", [])
        dd_nics = policy.get("ddNic", [])

        for index in range(len(dp_types)):
            stage = {
                "type": dp_types[index],
                "ddName": dd_names[index] if index < len(dd_names) else None,
                "suName": su_names[index] if index < len(su_names) else None,
                "ddNic": dd_nics[index] if index < len(dd_nics) else None,
            }
            policy_data["stages"].append(stage)

        result["policies"].append(policy_data)

    return json.dumps(result, indent=2)


def format_yaml_output(policies, api_v3):
    """Format policies as YAML output"""
    lines = [f"policies_count: {len(policies)}", "policies:"]
    for policy in policies:
        lines.append(f"  - name: {policy.get('name')}")
        lines.append(f"    id: {policy.get('id')}")
        lines.append(f"    asset_type: {policy.get('assetType')}")
        if api_v3:
            lines.append(f"    disabled: {policy.get('disabled', False)}")
        else:
            lines.append(f"    enabled: {policy.get('enabled', True)}")

        dp = policy.get("dpType", [])
        dd = policy.get("ddName", [])
        su = policy.get("suName", [])
        nic = policy.get("ddNic", [])

        if dp:
            lines.append("    stages:")
            for i in range(len(dp)):
                lines.append(f"      - type: {dp[i]}")
                if i < len(dd):
                    lines.append(f"        dd_name: {dd[i]}")
                else:
                    lines.append("        dd_name: N/A")
                if i < len(su):
                    lines.append(f"        su_name: {su[i]}")
                else:
                    lines.append("        su_name: N/A")
                if i < len(nic):
                    lines.append(f"        dd_nic: {nic[i]}")
                else:
                    lines.append("        dd_nic: N/A")

    return "\n".join(lines) + "\n"


def format_csv_output(policies, api_v3):
    """Format policies as CSV output"""
    report = []
    for policy in policies:
        if api_v3:
            enabled = "false" if policy.get('disabled', False) else "true"
        else:
            enabled = "true" if policy.get('enabled', True) else "false"

        dp = policy.get("dpType", [])
        dd = policy.get("ddName", [])
        su = policy.get("suName", [])
        nic = policy.get("ddNic", [])

        row = {
            "name": policy.get("name", ""),
            "id": policy.get("id", ""),
            "asset_type": policy.get("assetType", ""),
            "enabled": enabled
        }

        for i in range(len(dp)):
            col_suffix = f"stage{i + 1}"
            row[f"{col_suffix}_type"] = dp[i]
            row[f"{col_suffix}_dd_name"] = dd[i] if i < len(dd) else "N/A"
            row[f"{col_suffix}_su_name"] = su[i] if i < len(su) else "N/A"
            row[f"{col_suffix}_dd_nic"] = nic[i] if i < len(nic) else "N/A"

        report.append(row)

    headers = list(report[0].keys()) if report else []
    lines = [",".join(headers)]
    
    for item in report:
        values = []
        for h in headers:
            val = str(item[h])
            if "," in val:
                val = f'"{val}"'
            values.append(val)
        lines.append(",".join(values))

    return "\n".join(lines) + "\n"


def main():
    api_port = "8443"
    api_endpoint = "/api/v2"
    api_v3_endpoint = "/api/v3"
    api_v3_release = 19.16

    args = get_args()
    ppdm = args.server
    user = args.user
    policy_name = args.name

    if args.envpassword:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            print("Error: PPDM_PASSWORD environment variable not set")
            raise SystemExit(1)
    elif args.password:
        password = args.password
    else:
        print("Error: Password required (-pwd or -envpassword)")
        raise SystemExit(1)

    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(ppdm, user, password, uri)
    version = get_version(uri, token)
    version_float = parse_version(version)

    api_v3 = False
    if version_float >= api_v3_release:
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
        policy = get_storage_info(policy, api_v3)
        policy = get_dd_name(uri, token, policy)
        policy = get_dd_storageunit(uri, token, policy)

    if args.output == "json":
        output = format_json_output(policies)
    elif args.output == "yaml":
        output = format_yaml_output(policies, api_v3)
    elif args.output == "csv":
        output = format_csv_output(policies, api_v3)
    else:
        output = format_text_output(policies, api_v3)

    if args.file:
        with open(args.file, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Output written to: {args.file}")
    else:
        print(output)


if __name__ == "__main__":
    main()
