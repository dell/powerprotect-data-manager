#!/usr/bin/env python3

"""
Automate PVC exclusion in Dell PowerProtect Data Manager k8s data protection.

Author: Idan Kentor <idan.kentor@dell.com>
Version: 2 - July 2026
Copyright: [2024-2026] [Idan Kentor]

Example usage:
    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p "MyPwd!" \
      -a exclude -pvc mysql1 -ns mysql

    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -envpassword \
      -a include -pvc maria -ns maria -native
    
    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p "MyPwd!" \
      -a batch
    
    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -envpassword \
      -a batch -native
    
    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p "MyPwd!" \
      -a list -cl k8s_prod1
    
    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 -p "MyPwd!" \
      -a exclude -pvc mysql1 -ns mysql -oc

    python ppdm_exclude_pvc.py -ppdm 10.0.0.1 \
      -a print-cmd -pvc mysql1 -ns mysql
"""

import argparse
import json
import os
import subprocess
import sys
import requests
import urllib3

if "-native" not in sys.argv:
    try:
        from kubernetes import config, dynamic
        from kubernetes.client import api_client
        NATIVE_API = False
    except (ImportError, ModuleNotFoundError):
        NATIVE_API = True
else:
    NATIVE_API = True


urllib3.disable_warnings()


def get_args():
    """Gets command line args from the user"""
    parser = argparse.ArgumentParser(
        description="Automate PVC exclusion in Dell PPDM k8s data protection",
        epilog="Batch mode annotation: ppdm.config.exclude/pvc=yes|no. "
               "After exclude/include, the matching kubectl or oc annotate command is printed."
    )

    parser.add_argument(
        "-ppdm", "--ppdm",
        required=True,
        help="PPDM server FQDN or IP",
    )

    parser.add_argument(
        "-u", "--username",
        default="admin",
        help="PPDM username (default: admin)",
    )

    parser.add_argument(
        "-p", "--password",
        help="PPDM password",
    )

    parser.add_argument(
        "-envpassword", "--env-password",
        dest="env_password",
        action="store_true",
        help="Read password from PPDM_PASSWORD environment variable",
    )

    parser.add_argument(
        "-a", "--action",
        required=True,
        choices=["exclude", "include", "batch", "list", "print-cmd"],
        help=("list: list PVCs | "
              "exclude/include: exclude or include a specific PVC | "
              "batch: process PVCs annotated with ppdm.config.exclude/pvc=yes|no | "
              "print-cmd: print the annotate command for a PVC and exit"),
    )

    parser.add_argument(
        "-pvc", "--volume-name",
        dest="pvc",
        help="PVC volume name",
    )

    parser.add_argument(
        "-ns", "--namespace",
        dest="ns",
        help="Optionally provide the relevant namespace",
    )

    parser.add_argument(
        "-cl", "--cluster",
        help="Optionally filter listings to a specific k8s cluster",
    )

    parser.add_argument(
        "-native", "--native",
        action="store_true",
        help="Use native kubectl/oc instead of the kubernetes Python client",
    )

    parser.add_argument(
        "-oc", "--openshift",
        dest="oc",
        action="store_true",
        help="Use 'oc' instead of 'kubectl' for all commands (OpenShift clusters)",
    )

    return parser.parse_args()


def get_volume_details(ns=None, pvc_name=None, annotation=None):
    """Get PVC details via Kubernetes module"""
    kube_config = config.load_kube_config()
    client = dynamic.DynamicClient(api_client.ApiClient(configuration=kube_config))
    api = client.resources.get(api_version="v1", kind="PersistentVolumeClaim")
    exclude_pvcs = []

    if ns:
        pvcs = api.get(namespace=ns)
    else:
        pvcs = api.get()

    for pvc in pvcs.items:
        if pvc_name:
            if pvc_name == pvc.metadata.name:
                return pvc.metadata.name
        if annotation:
            for label, value in (pvc.metadata.annotations or {}).items():
                if label == annotation:
                    if value in ("yes", "no"):
                        exclude_pvcs.append({pvc.metadata.name: value})
                            
    if exclude_pvcs:
        return exclude_pvcs

    return False


def get_volume_details_native(ns=None, pvc_name=None, annotation=None, cli=None):
    """Get PVC details via kubectl or oc"""
    exclude_pvcs = []

    if ns:
        command = f"{cli} get pvc -n {ns} -o json"
    else:
        command = f"{cli} get pvc -A -o json"

    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    pvcs, error = process.communicate()

    if not pvcs or error:
        raise SystemExit("No PVCs detected. Exiting...")

    pvcs = json.loads(pvcs)

    for pvc in pvcs["items"]:
        if pvc_name:
            if pvc_name == pvc["metadata"]["name"]:
                return pvc["metadata"]["name"]
        if annotation:
            for label, value in (pvc["metadata"].get("annotations") or {}).items():
                if label == annotation:
                    if value in ("yes", "no"):
                        exclude_pvcs.append({pvc["metadata"]["name"]: value})

    if exclude_pvcs:
        return exclude_pvcs

    return False


def determine_asset_id(uri, token, pvc_name, ns=None):
    """Determines the asset ID based on PVC name and optional namespace"""
    uri = f"{uri}/assets"
    query = 'type eq "KUBERNETES" and subtype eq "K8S_PERSISTENT_VOLUME_CLAIM"'
    pvc_query = f'{query} and name eq "{pvc_name}"'

    if ns:
        pvc_query += f' and details.k8s.namespace eq "{ns}"'
    params = {"filter": pvc_query}

    response = init_rest_call("GET", uri, token, None, params)

    if not response or len(response["content"]) == 0:
        return False

    if len(response["content"]) == 1:
        return response["content"][0]["id"]

    return False


def list_pvc_volumes(uri, token, cluster=None, ns=None):
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
        if ns:
            if pvc_details["namespace"] != ns:
                continue
        pvc_report = {
            "name": pvc["name"],
            "assetID": pvc["id"],
            "pvcID": f"pvc-{pvc_details['uid']}",
            "namespace": pvc_details["namespace"],
            "AssetSource": pvc_details["inventorySourceName"],
            "protectionStatus": pvc["protectionStatus"],
            "protectionPolicy": pvc["protectionPolicy"]["name"] if pvc["protectionPolicy"] else None,
            "sizeInGB": pvc["size"] / (1024**3),
            "excluded": pvc_details["persistentVolumeClaim"]["excluded"],
            "storageClass": pvc_details["persistentVolumeClaim"]["storageClassName"],
            "accessModes": str(pvc_details["persistentVolumeClaim"]["accessModes"][0]),
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
        action = "excluded" if exclude else "included"
        print(f"Asset ID {asset_id} was {action} successfully")

    return response


def init_rest_call(verb, uri, token, payload=None, params=None):
    """Generic function for REST calls"""
    if uri.endswith("/login"):
        headers = {"Content-Type": "application/json"}
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
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
        print(f"-> Connection timed out {uri}: {error}")
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
    args = get_args()

    ppdm, username = args.ppdm, args.username
    action, pvc, ns, cluster = args.action, args.pvc, args.ns, args.cluster
    native = True if NATIVE_API else args.native
    cli = "oc" if args.oc else "kubectl"

    if action == "print-cmd":
        if not pvc:
            print("PVC name is required for print-cmd. Use -pvc <name>. Exiting...")
            raise SystemExit(1)
        ns_flag = f" -n {ns}" if ns else ""
        print(f"{cli} annotate pvc {pvc}{ns_flag} ppdm.config.exclude/pvc=yes --overwrite")
        raise SystemExit(0)

    # Get password from a command line argument or environment variable
    if args.password:
        password = args.password
    elif args.env_password:
        password = os.environ.get("PPDM_PASSWORD")
        if not password:
            print("PPDM_PASSWORD environment variable is not set. Exiting...")
            raise SystemExit(1)
    else:
        print("Password is required. Use -p or -envpassword. Exiting...")
        raise SystemExit(1)

    annotation = "ppdm.config.exclude/pvc"
    api_endpoint = "/api/v2"
    api_port = 8443

    uri = f"https://{ppdm}:{api_port}{api_endpoint}"
    token = authenticate(uri, username, password)

    if action in ("exclude", "include"):
        exclude = bool(action == "exclude")
        if native:
            pvc_volname = get_volume_details_native(ns, pvc, None, cli)
        else:
            pvc_volname = get_volume_details(ns, pvc)
        if pvc_volname:
            asset_id = determine_asset_id(uri, token, pvc_volname, ns)
            if not asset_id:
                raise SystemExit(f"Could not find volume {pvc}")
            exclude_pvc(uri, token, asset_id, exclude)
            annot_value = "yes" if exclude else "no"
            ns_flag = f" -n {ns}" if ns else ""
            print(f"-> To sync the annotation on the PVC, run:")
            print(f"   {cli} annotate pvc {pvc}{ns_flag} ppdm.config.exclude/pvc={annot_value} --overwrite")
        else:
            raise SystemExit(f"Could not find volume {pvc}")
    elif action == "batch":
        if native:
            exclude_pvcs = get_volume_details_native(ns, None, annotation, cli)
        else:
            exclude_pvcs = get_volume_details(ns, None, annotation)
        if exclude_pvcs:
            for pvc in exclude_pvcs:
                for pvc_volname, exclude in pvc.items():
                    asset_id = determine_asset_id(uri, token, pvc_volname, ns)
                    if not asset_id:
                        raise SystemExit("No volumes found for exclusion")
                    exclude = bool(exclude == "yes")
                    exclude_pvc(uri, token, asset_id, exclude)
        else:
            raise SystemExit("No volumes found for exclusion")
    elif action == "list":
        pvc_volumes = list_pvc_volumes(uri, token, cluster, ns)
        if not pvc_volumes:
            raise SystemExit("No volumes found")
        print(f"Total: {len(pvc_volumes)} PVCs")
        print(json.dumps(pvc_volumes, indent=4))

    print("-> All tasks have been completed")


if __name__ == "__main__":
    main()
