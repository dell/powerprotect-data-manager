#!/usr/bin/env python3

import argparse
import requests
import urllib3
import json
import sys
import time
from datetime import datetime

# Perform File Level Recovery in PowerProtect

urllib3.disable_warnings()

def get_args():
    # Get command line args from the user
    parser = argparse.ArgumentParser(
        description='Script to update Protection Policy Schedule in PowerProtect Data Manager')
    parser.add_argument('-s', '--server', required=True,
                        action='store', help='PPDM DNS name or IP')
    parser.add_argument('-usr', '--user', required=False, action='store',
                        default='admin', help='User')
    parser.add_argument('-pwd', '--password', required=True, action='store',
                        help='Password')
    parser.add_argument('-name', '--vmname', required=True, action='store',
                        help='Provide the name of the protected VM')
    parser.add_argument('-action', '--action', required=True, choices=['list_files', 'recover_files'],
                        help='Choose to list or recover files')
    parser.add_argument('-dir', '--dir', required=('list_files' in sys.argv), action='store',
                        help='The directory to list the files under it.')
    parser.add_argument('-files', '--filenames', required=('recover_files' in sys.argv), action='store',
                        help='Provide the names of the files(comma separated) to be restored')
    parser.add_argument('-overwrite', '--overwrite', required=('recover_files' in sys.argv), choices=['yes', 'no'],
                        help='Choose to overwrite existing files or not')
    parser.add_argument('-targetuser', '--targetuser', required=True, action='store',
                        help='Provide the username of the target VM')
    parser.add_argument('-targetpwd', '--targetpassword', required=True, action='store',
                        help='Provide the password of the target VM')
    args = parser.parse_args()
    return args

def authenticate(ppdm, user, password, uri):
    # Login
    print('\nRetrieving authorization token')
    loginendpoint = '/login'
    uri += loginendpoint
    headers = {'Content-Type': 'application/json'}
    payload = '{"username": "%s", "password": "%s"}' % (user, password)

    try:
        response = requests.post(
            uri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('Login failed for user: {}, code: {}, body: {}'.format(
            user, response.status_code, response.text))
        print('\nUser: {} logged in to PPDM: {}'.format(user, ppdm))
        # Parse the response and extract the access_token
        accesstoken = response.json()['access_token']
        return accesstoken
    except requests.exceptions.ConnectionError as errc:
        print('\nError Connecting to {}: {}'.format(ppdm, errc))
        sys.exit()
    except requests.exceptions.Timeout as errt:
        print('\nConnection timed out, make sure that there is connectivity to {}: {}'.format(
            ppdm, errt))
        sys.exit()
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def get_asset_details(uri, accesstoken, assetname):
    # Get asset id using the type and name
    print('\nFetching Virtual Machine using name: {}'.format(assetname))
    assetsendpoint = '/assets'
    assetsapifilter = '?filter=type%20eq%20%22VMWARE_VIRTUAL_MACHINE%22%20and%20name%20lk%20%22%25'+assetname+'%25%22'
    uri = uri + assetsendpoint + assetsapifilter
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nCould not fetch asset details: , code: {}, body: {}'.format(
            response.status_code, response.text))
        if len(response.json()['content']) == 0:
            print('\nNo asset found matching criteria - name: {}'.format(assetname))
            sys.exit()
        elif len(response.json()['content']) > 1:
            print(
                '\nMultiple assets found matching criteria. Please refine the search further.')
            sys.exit()
        else:
            assetid = response.json()['content'][0]['id']
            assetname = response.json()['content'][0]['name']
            print('\nAsset id = {}, Asset name: {}'.format(assetid, assetname))
            return assetid, assetname
    except requests.exceptions.RequestException:
        print('\nThe call {}{} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def get_latest_copy(uri, accesstoken, assetid, assetname):
    # Fetch the backup copies available for the asset
    print('\nFetching available backup copies for asset: {}'.format(assetname))
    copiesendpoint = '/assets/' + assetid + '/copies'
    copiesapifilter = '?orderby=createTime%20DESC'
    uri += copiesendpoint + copiesapifilter
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        # Get the latest copy
        response = requests.get(uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nFailed to get copies for asset: {}, code: {}, body: {}'.format(
            assetname, response.status_code, response.text))
        if response.json()['content']:
            copyid = response.json()['content'][0]['id']
            print('\nLatest Backup Copy id: {}, Created at {}'.format(
                copyid, response.json()['content'][0]['createTime']))
            return copyid
        else:
            print("\nNo backup copies found for the asset: {}".format(assetname))
            sys.exit()
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def create_flr_session(uri, accesstoken, assetid, copyid, targetuser, targetpassword):
    # Create an FLR session
    print('\nCreating an FLR session')
    flrsessionendpoint = '/flr-sessions'
    uri += flrsessionendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    payload = json.dumps({
                'copyId': copyid, 
                'removeAgent': 'true', 
                'targetPassword': targetpassword,
                'targetUser': targetuser, 
                'targetVmAssetId': assetid, 
                'timeout': 300
		    })
    try:
        response = requests.post(uri, headers=headers,
                                 data=payload, verify=False)
        response.raise_for_status()
        if response.status_code not in [200, 201, 202]:
            raise Exception('\nFailed to create FLR session, code: {}, body: {}'.format(response.status_code, response.text))
        # Creating of an FLR session is an asynchronous operation. So, get the activity id to monitor the progress.
        activityid = get_activity_id_from_response(response.json())
        flrsessionid = response.json()['flrSessionId']
        print('\nFLR session creation - Activity id: {}'.format(activityid))
        return activityid, flrsessionid
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def get_activity_id_from_response(response):
    # Parse the activity id from the response body
    if 'activityId' in response:
        return response['activityId']
    if 'taskId' in response:
        return response['taskId']
    if 'jobId' in response:
        return response['jobId']
    return None

def monitor_task_status(uri, accesstoken, activityid):
    # Monitor the creation of the FLR session
    print('\nMonitoring activity: {}'.format(activityid))
    monitoractivityendpoint = '/activities/' + activityid
    uri += monitoractivityendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    sleepinterval = 10
    timeout = 300
    # Monitor the task till it succeeds, fails or times out
    starttime = datetime.now()
    while True:
        if (datetime.now() - starttime).total_seconds() > timeout:
            break
        try:
            response = requests.get(uri, headers=headers, verify=False)
            response.raise_for_status()
            if (response.status_code != 200):
                raise Exception('\nUnable to monitor task: {}, code: {}, body: {}'.format(
                uri, response.status_code, response.text))
            # Check for success status
            taskstatus = response.json()['state']
            print('\nTask status: {}'.format(taskstatus))
            if taskstatus == 'COMPLETED':
                return response.json()['result']['status'], response.json()
            time.sleep(sleepinterval)
        except requests.exceptions.RequestException:
            print('\nThe call {} {} failed with exception:{}'.format(
                response.request.method, response.url, response.text))
            sys.exit()
    return 'TIMEOUT', response.json()

def get_directory_file_list(uri, accesstoken, flrsessionid, dir):
    # Get the directory file list
    filelistendpoint = '/flr-sessions/' + flrsessionid + '/files'
    getfilelisturi = uri + filelistendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        change_directory(uri, accesstoken, flrsessionid, dir)
        print('\nGetting the directory file list')
        response = requests.get(getfilelisturi, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nFailed to get file list, code: {}, body: {}'.format(
            response.status_code, response.text))
        print(response.text)
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def change_directory(uri, accesstoken, flrsessionid, dir):
    # Changes Directory for list listing
    print('\nChanging directory')
    urllib3.disable_warnings()
    dirchangeendpoint = '/flr-sessions/' + flrsessionid
    changediruri = uri + dirchangeendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    payload = json.dumps({
        "browseDest": "false", 
        "directory": dir
        })
    try:
        response = requests.put(changediruri, data=payload, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 200):
            raise Exception('\nFailed to change directory to: {}, code: {}, body: {}'.format(
            dir, response.status_code, response.text))
        print(response.text)
    except requests.exceptions.RequestException:
            print('\nThe call {} {} failed with exception:{}'.format(
                response.request.method, response.url, response.text))
            delete_flr_session(uri, accesstoken, flrsessionid)
            sys.exit()

def restore_files(uri, accesstoken, flrsessionid, filenames, overwrite):
    # Restore specified files
    print('\nRestoring the specified files')
    urllib3.disable_warnings()
    restorefilesendpoint = '/flr-sessions/' + flrsessionid + '/tasks'
    restorefilesuri = uri + restorefilesendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    payload = json.dumps({
        "filePaths": filenames.split(','), 
        "overwriteExisting": overwrite,
        "restoreToOriginalPath": "true", 
        "targetDirectory": ""
        })
    try:
        print(filenames)
        response = requests.post(restorefilesuri, headers=headers, data=payload, verify=False)
        response.raise_for_status()
        if response.status_code not in [200, 201, 202]:
            raise Exception('\nFailed to restore files, code: {}, body: {}'.format(response.status_code, response.text))
        # Restoring a file is an asynchronous operation. So, get the task URL to monitor the progress.
        activityid = get_activity_id_from_response(response.json())
        print('\nRestore file(s) - activity id: {}'.format(activityid))
        return activityid
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        delete_flr_session(uri, accesstoken, flrsessionid)
        sys.exit()

def delete_flr_session(uri, accesstoken, flrsessionid):
    # Deleting the FLR session
    print('\nDeleting the FLR session')
    deleteflrsessionendpoint = '/flr-sessions/' + flrsessionid
    deleteflrsessionuri = uri + deleteflrsessionendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        response = requests.delete(deleteflrsessionuri, headers=headers, verify=False)
        response.raise_for_status()
        if response.status_code not in [200, 202, 204]:
            raise Exception('\nFailed to delete FLR session: {}, code: {}, body: {}'.format(
                            flrsessionid, response.status_code, response.text))
        activityid = get_activity_id_from_response(response.json())
        print('\nDelete FLR session - activity id: {}'.format(activityid))
        status, response = monitor_task_status(uri, accesstoken, activityid)
        print('\nDelete FLR session - status: {}'.format(status))
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def logout(ppdm, user, uri, accesstoken):
    # Logs out of PowerProtect
    print('\nLogging out of the current session')
    logoutendpoint = '/logout'
    uri += logoutendpoint
    headers = {'Content-Type': 'application/json',
               'Authorization': 'Bearer {}'.format(accesstoken)}
    try:
        response = requests.post(
            uri, headers=headers, verify=False)
        response.raise_for_status()
        if (response.status_code != 204):
            raise Exception('\nLogout failed for user: {}, code: {}, body: {}'.format(
            user, response.status_code, response.text))
        print('\nUser: {} logged out of PPDM: {}'.format(user, ppdm))
    except requests.exceptions.RequestException:
        print('\nThe call {} {} failed with exception:{}'.format(
            response.request.method, response.url, response.text))
        sys.exit()

def main():
    port = '8443'
    apiendpoint = '/api/v2'
    args = get_args()
    ppdm = args.ppdm
    user = args.user
    password = args.password
    vmname = args.vmname
    filenames = args.filenames
    targetuser = args.targetuser
    targetpassword = args.targetpassword
    action = args.action
    overwrite = False if args.overwrite == 'no' else True
    dir = args.dir
    uri = 'https://{}:{}{}'.format(ppdm, port, apiendpoint)
    accesstoken = authenticate(ppdm, user, password, uri)
    assetid, assetname = get_asset_details(uri, accesstoken, vmname)
    copyid = get_latest_copy(uri, accesstoken, assetid, assetname)
    activityid, flrsessionid = create_flr_session(
        uri, accesstoken, assetid, copyid, targetuser, targetpassword)
    status, response = monitor_task_status(uri, accesstoken, activityid)
    if status == 'OK':
        if 'list_files' == action:
            if status == 'OK':
                get_directory_file_list(uri, accesstoken, flrsessionid, dir)
                delete_flr_session(uri, accesstoken, flrsessionid)
        else:
            if status == 'OK':
                activityid = restore_files(
                    uri, accesstoken, flrsessionid, filenames, overwrite)
                status, response = monitor_task_status(uri, accesstoken, activityid)
                # Restore files API will automatically delete the FLR session.
                # delete_flr_session(uri, accesstoken, flrsessionid)
    else:
        print('\nFLR session could not be created, error: {}'.format(response['result']['error']['reason']))
    logout(ppdm, user, uri, accesstoken)

if __name__ == "__main__":
    main()
