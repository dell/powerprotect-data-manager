# Dell PowerProtect Data Manager — Automation Scripts

[![Platform](https://img.shields.io/badge/platform-PowerProtect%20Data%20Manager-blue?logo=dell&logoColor=white)](https://www.dell.com/en-us/dt/data-protection/powerprotect-data-manager.htm)
[![Python](https://img.shields.io/badge/python-3.x-blue?logo=python&logoColor=white)](https://www.python.org/)
[![PowerShell](https://img.shields.io/badge/powershell-7.x-blue?logo=powershell&logoColor=white)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?logo=apache&logoColor=white)](LICENSE)
[![API Docs](https://img.shields.io/badge/API-Dell%20Developer%20Portal-orange?logo=swagger&logoColor=white)](https://developer.dell.com/apis/4378/versions/20.1.0)

A collection of automation scripts for [Dell PowerProtect Data Manager](https://www.dell.com/en-us/dt/data-protection/powerprotect-data-manager.htm) covering asset management, protection policies, backup, recovery, Kubernetes data protection, and lifecycle operations — all via the PPDM REST API.

---

## Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Python Scripts](#python-scripts)
  - [Protection Policies and Backup](#protection-policies-and-backup)
  - [Recovery](#recovery)
  - [Kubernetes](#kubernetes)
  - [Deployment and Upgrade](#deployment-and-upgrade)
  - [Asset and Infrastructure Management](#asset-and-infrastructure-management)
- [Authentication Helper](#authentication-helper)
- [Documentation](#documentation)
- [Authors](#authors)

---

## Prerequisites

| Requirement | Version |
| --- | --- |
| Python | 3.x |
| PowerShell | 7.x |
| `requests` | `pip install requests` |
| `urllib3` | `pip install urllib3` |
| `cryptography` *(secure_login_helper only)* | `pip install cryptography` |
| `kubernetes` *(K8s scripts, optional)* | `pip install kubernetes` |

All scripts accept `-h` / `--help` for a full argument reference:

```bash
python adhocbck.py -h
```

---

## Quick Start

Most scripts share the same connection pattern: server, user, password, and an action flag.

```bash
# Ad-hoc backup of a VM by name (monitors until completion)
python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -a backup -n myvm01 -t vmw_vm

# Create a daily VM protection policy
python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -a create -n VMpolicy1 -asset testvm* \
  -storage_name DD2 -dm TSDM \
  -freq daily -stime 09:00:00 -d 2 -ret "3 days"

# Kubernetes self-service backup of a namespace
python ppdm_k8s_self_service.py -ppdm 10.0.0.1 -p "myPassword!" \
  -a backup -ns my-app -cl k8s_prod1

# Deploy a new PPDM appliance from a config file
python Python/ppdm_deploy/ppdm_deploy.py --config Python/ppdm_deploy/config.json
```

> **Tip:** Avoid passing passwords in plain text — use the `PPDM_PASSWORD` environment variable or the Fernet-encrypted credential helper. See [Authentication Helper](#authentication-helper).

---

## Python Scripts

### Protection Policies and Backup

| Script | Description |
| --- | --- |
| [`addpolicy.py`](Python/addpolicy.py) | Create or list VM and Kubernetes protection policies. Supports hourly, daily, weekly, and monthly schedules with configurable retention. |
| [`updateprotectionpolicyschedule.py`](Python/updateprotectionpolicyschedule.py) | Display or update the backup schedule of an existing protection policy for a given asset. |
| [`policy2dd.py`](Python/policy2dd.py) | Show the Data Domain storage mapping for one or all protection policies — displays DD name, NIC, and storage unit per policy stage. |
| [`adhocbck.py`](Python/adhocbck.py) | Run ad-hoc backups for VMware VMs, Hyper-V VMs, Nutanix VMs, NativeEdge VMs, PowerMax storage groups, PowerStore volume groups, or Kubernetes namespaces. Monitors activity to completion. Supports saving the activity ID to a file for pipeline chaining. |

**Example — create a daily VM protection policy:**

```bash
python addpolicy.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -a create -n VMpolicy1 -asset testvm* \
  -storage_name DD2 -dm TSDM \
  -freq daily -stime 09:00:00 -d 2 -ret "3 days"
```

**Example — ad-hoc backup with activity monitoring:**

```bash
python adhocbck.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -a backup -n myvm01 -t vmw_vm
```

**Supported asset types for `adhocbck.py`:**

| Flag | Asset Type |
| --- | --- |
| `vmw_vm` | VMware Virtual Machine *(default)* |
| `hyperv_vm` | Hyper-V Virtual Machine |
| `nutanix_vm` | Nutanix Virtual Machine |
| `nativeedge_vm` | Dell NativeEdge VM |
| `pmax` | PowerMax Storage Group |
| `pstore` | PowerStore Volume Group |
| `k8s` | Kubernetes Namespace |

---

### Recovery

| Script | Description |
| --- | --- |
| [`restorevmorig.py`](Python/restorevmorig.py) | List available backups for a protected VM and restore to its original location using a specified backup ID. |
| [`filelevelrestore.py`](Python/filelevelrestore.py) | Perform file-level recovery (FLR) from a VM backup — mount a copy and retrieve individual files. |

**Example — restore a VM to its original location:**

```bash
# List available backups first
python restorevmorig.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -n myvm01 -a get_backups

# Restore using a backup ID
python restorevmorig.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -n myvm01 -a recover -bckid <backup-id>
```

---

### Kubernetes

| Script | Description |
| --- | --- |
| [`ppdm_k8s_self_service.py`](Python/ppdm_k8s_self_service.py) | Self-service backup and restore for Kubernetes namespaces. Supports restore-to-namespace (RTN), restore-to-existing (RTE), and cross-cluster restore. Outputs results as text, JSON, or YAML. |
| [`ppdm_k8s_reporting.py`](Python/ppdm_k8s_reporting.py) | Backup statistics report for protected Kubernetes namespaces — PVC counts, backup history, protection capacity, and unprotected namespace detection. Outputs as table, JSON, YAML, or CSV. |
| [`ppdm_exclude_pvc.py`](Python/ppdm_exclude_pvc.py) | List, exclude, or include specific Persistent Volume Claims (PVCs) from Kubernetes backup policies. Supports batch exclusion via annotations and both the Python `kubernetes` client and native `kubectl`. |
| [`credsmgmt.py`](Python/credsmgmt.py) | Add or remove Kubernetes service-account token credentials in PPDM used for cluster authentication. |

**Example — back up a Kubernetes namespace:**

```bash
python ppdm_k8s_self_service.py -ppdm 10.0.0.1 -p "myPassword!" \
  -a backup -ns my-app -cl k8s_prod1
```

**Example — restore a namespace to an alternate cluster:**

```bash
python ppdm_k8s_self_service.py -ppdm 10.0.0.1 -envpassword \
  -a rte -ns my-app -cl k8s_prod1 \
  -alt-cluster k8s_dr1 -target-ns my-app-restored
```

**Example — backup report (JSON output to file):**

```bash
python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
  -cl k8s_prod1 -o json -f report.json
```

---

### Deployment and Upgrade

| Folder / Script | Description |
| --- | --- |
| [`ppdm_deploy/`](Python/ppdm_deploy/) | Automated initial deployment and configuration of a freshly deployed PPDM appliance. Drives the first-run wizard via the REST API using a JSON config file. |
| [`ppdm_upgrade/`](Python/ppdm_upgrade/) | Automated PPDM upgrade — upload the upgrade package, run pre-checks, start the upgrade, and monitor progress. |

**Example — deploy a new PPDM appliance:**

```bash
# Copy and edit the config template first
cp Python/ppdm_deploy/config-minimal.json my-config.json

# Run the deployment
python Python/ppdm_deploy/ppdm_deploy.py --config my-config.json
```

See the `README.md` inside each subfolder for full config reference.

---

### Asset and Infrastructure Management

| Script | Description |
| --- | --- |
| [`assetmgmt.py`](Python/assetmgmt.py) | Discover and list assets by inventory source type (vCenter, K8s, Data Domain). Triggers discovery jobs and monitors completion. |
| [`removeassetsrc.py`](Python/removeassetsrc.py) | List or remove inventory / asset sources (vCenter, Data Domain, Kubernetes clusters) by name, ID, or type. |
| [`certmgmt.py`](Python/certmgmt.py) | List or accept TLS certificates for PPDM-registered hosts (e.g. OpenShift API endpoints, vCenter). |

**Example — accept a certificate for a newly registered host:**

```bash
python certmgmt.py -s 10.0.0.1 -usr admin -pwd "myPassword!" \
  -a accept -host api.mycluster.example.com
```

---

## Authentication Helper

Two options are available to avoid passing passwords in plain text.

### Option 1 — Environment Variable (simplest)

Scripts that support `-envpassword` / `--env-password` read the password from the `PPDM_PASSWORD` environment variable:

```bash
# Set once in your shell session
export PPDM_PASSWORD="myPassword!"          # Linux / macOS
$env:PPDM_PASSWORD = "myPassword!"         # PowerShell

# Then run any supporting script without -pwd
python ppdm_k8s_self_service.py -ppdm 10.0.0.1 -envpassword \
  -a backup -ns my-app -cl k8s_prod1

python ppdm_k8s_reporting.py -ppdm 10.0.0.1 -envpassword \
  -cl k8s_prod1 -o json
```

Scripts that support this flag include `ppdm_k8s_self_service.py`, `ppdm_k8s_reporting.py`, and `ppdm_exclude_pvc.py`.

### Option 2 — Encrypted Credential File (persistent)

[`secure_login_helper.py`](Python/secure_login_helper.py) encrypts PPDM credentials using [Fernet symmetric encryption](https://cryptography.io/en/latest/fernet/) so scripts never need a plain-text password on the command line.

```bash
# Create encrypted credential files
python secure_login_helper.py \
  --secure-file-path c:\creds \
  --password "myPassword!" \
  --ppdm 10.0.0.1

# Clear plain-text password file after encryption
python secure_login_helper.py \
  --clear-password-file c:\creds\ppdm.pwd \
  --secure-file-path c:\creds
```

Requires: `pip install cryptography`

---

## Documentation

- **Script help pages** — run any script with `-h`, e.g. `python adhocbck.py -h`
- **PPDM REST API Reference** — [Dell Technologies API Explorer](https://developer.dell.com/apis/4378)
- **PPDM Product Documentation** — [Dell PowerProtect Data Manager Docs](https://dell.com/ppdmdocs)

---

## Authors

- **Idan Kentor** — [Dell Technologies](https://www.dell.com) *(Python scripts)*
- **Cliff Rodriguez** — [Dell Technologies](https://www.dell.com) *(PowerShell scripts)*
