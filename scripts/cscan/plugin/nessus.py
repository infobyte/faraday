#!/usr/bin/env python2
###
## Faraday Penetration Test IDE
## Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###
import requests
import json
import time
import sys
import argparse
import os
from config.constant import CONST_FARADAY_HOME_PATH
from server.config import FARADAY_BASE

my_env = os.environ

url = my_env["CS_NESSUS_URL"] if 'CS_NESSUS_URL' in my_env else "https://192.168.10.230:8834"
username = my_env["CS_NESSUS_USER"] if 'CS_NESSUS_USER' in my_env else "cscan"
password = my_env["CS_NESSUS_PASS"] if 'CS_NESSUS_PASS' in my_env else "XqjympHtrvVU22xtK5ZZ"
profile = my_env["CS_NESSUS_PROFILE"] if 'CS_NESSUS_PROFILE' in my_env else "Basic Network Scan"

verify = False
token = ''

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def build_url(resource):
    return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None):
    """
    Send a request

    Send a request to Nessus based on the specified data. If the session token
    is available add it to the request. Specify the content type as JSON and
    convert the data to JSON format.
    """
    headers = {'X-Cookie': 'token={0}'.format(token),
               'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

    # Exit if there is an error.
    if r.status_code != 200:
        e = r.json()
        print e['error']
        sys.exit()

    # When downloading a scan we need the raw contents not the JSON data. 
    if 'download' in resource:
        return r.content
    else:
        try:
            return r.json()
        except:
            pass


def login(usr, pwd):
    """
    Login to nessus.
    """
    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)

    return data['token']


def logout():
    """
    Logout of nessus.
    """

    connect('DELETE', '/session')


def get_policies():
    """
    Get scan policies

    Get all of the scan policies but return only the title and the uuid of
    each policy.
    """

    data = connect('GET', '/editor/policy/templates')

    return dict((p['title'], p['uuid']) for p in data['templates'])


def get_history_ids(sid):
    """
    Get history ids

    Create a dictionary of scan uuids and history ids so we can lookup the
    history id by uuid.
    """
    data = connect('GET', '/scans/{0}'.format(sid))

    return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
    """
    Scan history details

    Get the details of a particular run of a scan.
    """
    params = {'history_id': hid}
    data = connect('GET', '/scans/{0}'.format(sid), params)

    return data['info']


def add(name, desc, targets, pid):
    """
    Add a new scan

    Create a new scan using the policy_id, name, description and targets. The
    scan will be created in the default folder for the user. Return the id of
    the newly created scan.
    """

    scan = {'uuid': pid,
            'settings': {
                'name': name,
                'description': desc,
                'text_targets': targets}
            }

    data = connect('POST', '/scans', data=scan)

    return data['scan']


def update(scan_id, name, desc, targets, pid=None):
    """
    Update a scan

    Update the name, description, targets, or policy of the specified scan. If
    the name and description are not set, then the policy name and description
    will be set to None after the update. In addition the targets value must
    be set or you will get an "Invalid 'targets' field" error.
    """

    scan = {}
    scan['settings'] = {}
    scan['settings']['name'] = name
    scan['settings']['desc'] = desc
    scan['settings']['text_targets'] = targets

    if pid is not None:
        scan['uuid'] = pid

    data = connect('PUT', '/scans/{0}'.format(scan_id), data=scan)

    return data


def launch(sid):
    """
    Launch a scan

    Launch the scan specified by the sid.
    """

    data = connect('POST', '/scans/{0}/launch'.format(sid))

    return data['scan_uuid']


def status(sid, hid):
    """
    Check the status of a scan run

    Get the historical information for the particular scan and hid. Return
    the status if available. If not return unknown.
    """ 

    d = get_scan_history(sid, hid)
    return d['status']


def export_status(sid, fid):
    """
    Check export status

    Check to see if the export is ready for download.
    """

    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))

    return data['status'] == 'ready'


def export(sid):
    """
    Make an export request

    Request an export of the scan results for the specified scan and
    historical run. In this case the format is hard coded as nessus but the
    format can be any one of nessus, html, pdf, csv, or db. Once the request
    is made, we have to wait for the export to be ready.
    """

    data = {'format': 'nessus'}

    data = connect('POST', '/scans/{0}/export'.format(sid), data=data)

    fid = data['file']

    while export_status(sid, fid) is False:
        time.sleep(5)

    return fid


def download(sid, fid, output=None):
    """
    Download the scan results

    Download the scan results stored in the export file specified by fid for
    the scan specified by sid.
    """

    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
    # For version 7, use the nessus scan Id to avoid overwrite the output file
    if not output:
        print('Using Nessus 7. Ignore --output. This is normal.')
        report_path = os.path.join(FARADAY_BASE,'scripts','cscan','output','nessus_{0}.xml'.format(sid))
        if not os.path.exists(report_path):
            with open(report_path,'w') as report:
                print('Saving scan results to {0}.'.format(report_path))
                report.write(data)

    else:
        print('Saving scan results to {0}.'.format(output))
        with open(output, 'w') as report:
            report.write(data)


def delete(sid):
    """
    Delete a scan

    This deletes a scan and all of its associated history. The scan is not
    moved to the trash folder, it is deleted.
    """

    connect('DELETE', '/scans/{0}'.format(scan_id))


def history_delete(sid, hid):
    """
    Delete a historical scan.

    This deletes a particular run of the scan and not the scan itself. the
    scan run is defined by the history id.
    """

    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))

def get_scans():
    scan_list = []
    data = connect('GET','/scans')
    for scans in data['scans']:
        scans_info = {}
        scans_info['id'] =  scans['id']
        scans_info['creation_date'] =  scans['creation_date']
        scan_list.append(scans_info)
    
    scan_list = sorted(scan_list,key=lambda scan:scan['creation_date'])
    return scan_list

def get_date():
    with open(os.path.join(CONST_FARADAY_HOME_PATH,'cscan','date.txt'),'r') as date_file:
        date = date_file.read()
        try:
            date = int(date)
        except ValueError:
            # Default date: September 3, 2018 20:45 (GMT)
            return 1536007534

        return date

def set_date(date):
    with open(os.path.join(CONST_FARADAY_HOME_PATH,'cscan','date.txt'),'w') as date_file:
        date_file.write(str(date))

def get_version():
    data = connect('GET','/server/properties')
    return int(data['nessus_ui_version'][0])


def create_directory():
    if not os.path.exists(os.path.join(CONST_FARADAY_HOME_PATH,'cscan')):
        os.mkdir(os.path.join(CONST_FARADAY_HOME_PATH,'cscan'))
    if not os.path.exists(os.path.join(CONST_FARADAY_HOME_PATH,'cscan','date.txt')):
        open(os.path.join(CONST_FARADAY_HOME_PATH,'cscan','date.txt'),'w').close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='nessus_client is develop for automating security testing')
    parser.add_argument('-t', '--target', help='Network or Host for scan', required=False)
    parser.add_argument('-o', '--output', help='Output file', required=False)
    args = parser.parse_args()
    # Review de Command input
    if args.target is None or args.output is None:
        print "Argument errors check -h"
        exit(0)

    print('Login')
    try:
        token = login(username, password)
    except:
        print "Unexpected error:", sys.exc_info()[0]
        raise

    version = get_version()
    if version < 7 :
        #For Nessus <7
        print('Adding new scan.' + token)
        print args.target

        policies = get_policies()
        policy_id = policies[profile]
        scan_data = add('CScan nessus', 'Create a new scan with API', args.target, policy_id)
        scan_id = scan_data['id']

        print('Launching new scan.')
        scan_uuid = launch(scan_id)
        history_ids = get_history_ids(scan_id)
        history_id = history_ids[scan_uuid]
        while status(scan_id, history_id) not in ('completed', 'canceled'):
            time.sleep(5)

        print('Exporting the completed scan.')
        file_id = export(scan_id)
        download(scan_id, file_id, args.output)

        print('Deleting the scan.')
        history_delete(scan_id, history_id)
        delete(scan_id)

    else:
        #For Nessus >7
        create_directory()
        scans = get_scans()
        date = get_date()
        for scan in scans:
            if scan['creation_date'] > date:
                set_date(scan['creation_date'])
                print('Downloading scan. Id: {0}'.format(scan['id']))
                file_id = export(scan['id']) 
                download(scan['id'], file_id)
            else:
                print('Scan up to date. Id: {0}'.format(scan['id']))

    print('Logout')
    logout()