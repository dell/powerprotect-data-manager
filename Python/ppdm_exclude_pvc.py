#!/usr/bin/env python3

import argparse
import sys
import json
import subprocess
import requests
import urllib3

if "native" not in sys.argv:
    try:
        from kubernetes import config, dynamic
        from kubernetes.client import api_client
        NATIVE_API = False
    except (ImportError, ModuleNotFoundError):
        NATIVE_API = True

# Automates PVC exclusion in PowerProtect Data Manager k8s data protection
# Author - Idan Kentor <idan.kentor@dell.com>
# Version 1 - April 2024
# Copyright [2024] [Idan Kentor]

# Examples:
# python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p MyTempPwd123! -a exclude -pvc mysql1 -ns mysql
# python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p MyTempPwd123! -a include -pvc maria -ns maria -native
# python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p MyTempPwd123! -a batch
# python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p MyTempPwd123! -a batch -native
# python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p MyTempPwd123! -a list -cl k8s_prod1


urllib3.disable_warnings()


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Automate PVC exclusion in Dell PPDM k8s data protection"
    )
    parser.add_argument(
        "-ppdm",
        "--ppdm",
        required=False,
        dest="ppdm",
        action="store",
        help="Specify the PPDM server FQDN or IP ",
    )
    parser.add_argument(
        "-u",
        "--username",
        required=False,
        dest="username",
        action="store",
        default="admin",
        help="Optionally provide the PPDM username",
    )
    parser.add_argument(
        "-p",
        "--password",
        required=True,
        dest="password",
        action="store",
        help="PPDM password",
    )
    parser.add_argument(
        "-a",
        "--action",
        required=True,
        choices=["exclude", "include", "batch", "list"],
        help='List PVCs, exclude/include a specific PVC or exclude multiple PVCs'
    )
    parser.add_argument(
        "-pvc",
        "--volume-name",
        required=False,
        dest="pvc",
        action="store",
        help="Optionally provide the PVC volume name",
    )
    parser.add_argument(
        "-ns",
        "--namespace",
        required=False,
        dest="ns",
        action="store",
        help="Optionally provide the relevant namespace",
    )
    parser.add_argument(
        "-cl",
        "--cluster",
        required=False,
        dest="cluster",
        action="store",
        help="Optionally filter listings to a specific k8s cluster",
    )
    parser.add_argument(
        "-native",
        "--native",
        required=False,
        dest="native",
        action="store_true",
        help="Optionally use native kubectl",
    )

    args = parser.parse_args()
    return args


def get_volume_details(ns=None, pvc_name=None, annotation=None):
    """Get PVC details via Kubernetes module"""
    client = dynamic.DynamicClient(api_client.ApiClient(configuration=config.load_kube_config()))
    api = client.resources.get(api_version="v1", kind="PersistentVolumeClaim")
    exclude_pvcs = []
    if ns:
        pvcs = api.get(namespace=ns)
    else:
        pvcs = api.get()
    for pvc in pvcs.items:
        if pvc_name:
            if pvc_name == pvc.metadata.name:
                return pvc.spec.volumeName
        if annotation:
            for label in pvc.metadata.annotations:
                if label[0] == annotation:
                    if label[1] in ("yes", "no"):
                        exclude_pvcs.append({pvc.spec.volumeName: label[1]})
    if exclude_pvcs:
        return exclude_pvcs
    return False


def get_volume_details_native(ns=None, pvc_name=None, annotation=None):
    """Get PVC details via kubectl"""
    exclude_pvcs = []
    if ns:
        command = f"kubectl get pvc -n {ns} -o json"
    else:
        command = "kubectl get pvc -A -o json"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pvcs, error = process.communicate()
    if not pvcs or error:
        raise SystemExit("no PVCs detected, Existing...")
    pvcs = json.loads(pvcs)
    for pvc in pvcs["items"]:
        if pvc_name:
            if pvc_name == pvc["metadata"]["name"]:
                return pvc["spec"]["volumeName"]
        if annotation:
            for label in pvc["metadata"]["annotations"]:
                if label[0] == annotation:
                    if label[1] == "yes":
                        exclude_pvcs.append({pvc["spec"]["volumeName"]: label[1]})
    if exclude_pvcs:
        return exclude_pvcs
    return False


def determine_asset_id(uri, token, pvc_volname):
    """Determines the asset ID based on PVC volume name"""
    uri = f"{uri}/assets"
    query = 'type eq "KUBERNETES" and subtype eq "K8S_PERSISTENT_VOLUME_CLAIM"'
    pvc_query = f'{query} and details.k8s.persistentVolumeClaim.volumeName eq "{pvc_volname}"'
    params = {"filter": pvc_query}
    response = init_rest_call("GET", uri, token, None, params)
    if not response:
        return False
    if len(response["content"]) == 1:
        return response["content"][0]["id"]
    if len(response["content"]) == 0:
        pvc_uid = pvc_volname.split("pvc-")[1]
        pvc_query = f'{query} and details.k8s.uid eq "{pvc_uid}"'
        params = {"filter": pvc_query}
        response = init_rest_call("GET", uri, token, None, params)
        if len(response["content"]) == 1:
            return response["content"][0]["id"]
    return False


def list_pvc_volumes(uri, token, cluster=None):
    """Lists all PVC volumes"""
    uri = f"{uri}/assets"
    query = 'type eq "KUBERNETES" and subtype eq "K8S_PERSISTENT_VOLUME_CLAIM"'
    params = {"filter": query}
    response = init_rest_call("GET", uri, token, None, params)
    if not response:
        return False
    if len(response["content"]) == 0:
        return False
    pvc_volumes = []
    for pvc in response["content"]:
        pvc_details = pvc["details"]["k8s"]
        if cluster:
            if pvc_details["inventorySourceName"] != cluster:
                continue
        pvc_report = {
            "name": pvc["name"],
            "assetID": pvc["id"],
            "pvcID": f"pvc-{pvc_details['uid']}",
            "namespace": pvc_details["namespace"],
            "AssetSource": pvc_details["inventorySourceName"],
            "protectionStatus": pvc["protectionStatus"],
            "protectionPolicy": pvc["protectionPolicy"]["name"],
            "sizeInGB": pvc["size"] / (1024**3),
            "excluded": pvc_details["persistentVolumeClaim"]["excluded"],
            "storageClass": pvc_details["persistentVolumeClaim"]["storageClassName"],
            "accessModes": pvc_details["persistentVolumeClaim"]["accessModes"],
            "CreationDate": pvc_details["externalCreatedAt"],
            "deleted": pvc["deleted"]
        }
        pvc_volumes.append(pvc_report)
    return pvc_volumes


def exclude_pvc(uri, token, asset_id, exclude):
    """Excludes/includes PVC based on asset ID"""
    uri = f"{uri}/assets/{asset_id}"
    payload = {
        "id": asset_id,
        "details": {"k8s": {"persistentVolumeClaim": {"excluded": exclude}}}
        }
    response = init_rest_call("PATCH", uri, token, payload)
    if response:
        if exclude:
            action = "excluded"
        else:
            action = "included"
        print(f"Asset ID {asset_id} was {action} successfully")
    return response


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
    codes = {200, 201, 202, 204}
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
        print(f"{response.request.method} {response.url} failed with {error}")
    if uri.endswith("/login"):
        return response.json()["access_token"]
    if response.status_code not in codes:
        return False
    try:
        return response.json()
    except json.decoder.JSONDecodeError:
        if response.status_code == 204:
            return True
    return response.text


def authenticate(uri, username, password):
    """Login"""
    uri = f"{uri}/login"
    payload = {"username": username, "password": password}
    token = init_rest_call("POST", uri, payload, payload)
    return token


def main():
    # Args assignment

    args = get_args()
    ppdm, username, password = args.ppdm, args.username, args.password
    action, pvc, ns, cluster = args.action, args.pvc, args.ns, args.cluster
    if NATIVE_API:
        native = True
    else:
        native = args.native

    # Const definition
    annotation = "ppdm.config.exclude/pvc"
    api_endpoint = "/api/v2"
    api_port = 8443

    # Logs into the PPDM API
    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(uri, username, password)

    if action == "exclude" or action == "include":
        exclude = bool(action == "exclude")
        if native:
            pvc_volname = get_volume_details_native(ns, pvc)
        else:
            pvc_volname = get_volume_details(ns, pvc)
        if pvc_volname:
            asset_id = determine_asset_id(uri, token, pvc_volname)
            if not asset_id:
                raise SystemExit(f"Could not find volume {pvc}")
            exclude_pvc(uri, token, asset_id, exclude)
        else:
            raise SystemExit(f"Could not find volume {pvc}")
    elif action == "batch":
        if native:
            exclude_pvcs = get_volume_details_native(ns, None, annotation)
        else:
            exclude_pvcs = get_volume_details(ns, None, annotation)
        if exclude_pvcs:
            for pvc in exclude_pvcs:
                for pvc_volname, exclude in pvc.items():
                    asset_id = determine_asset_id(uri, token, pvc_volname)
                    if not asset_id:
                        raise SystemExit("No volumes found for exclusion")
                    exclude = bool(exclude == "yes")
                    exclude_pvc(uri, token, asset_id, exclude)
        else:
            raise SystemExit("No volumes found for exclusion")
    elif action == "list":
        pvc_volumes = list_pvc_volumes(uri, token, cluster)
        if not pvc_volumes:
            raise SystemExit("No volumes found")
        print(f"Total: {len(pvc_volumes)} PVCs")
        print(json.dumps(pvc_volumes, indent=4))
    print("-> All tasks have been completed")


if __name__ == "__main__":
    main()
