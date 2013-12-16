# pynessus.py
# Python module to interact with a Nessus 4.x scanner via XMLRPC.
# http://code.google.com/p/pynessus/
#
# Copyright (C) 2010 Dustin Seibel
#
# GNU General Public Licence (GPL)
# 
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59 Temple
# Place, Suite 330, Boston, MA  02111-1307  USA
#
# 2010-08-12:	0.1.0: Initial version.
# 2011-03-12:	0.2.1: Added a bunch of methods and robustified everything.
import sys
import urllib2
from urlparse import urljoin
from urllib import quote
import xml.etree.ElementTree as ET
import re
import datetime
import os
from random import randint

# Regex defs
re_unix_timestamp = re.compile('^\d{10}$')
re_unauthorized = re.compile('<title>200 Unauthorized</title>')

TOKEN_FILE = '.nessus_token'

# Plugin multi-value tags
PLUGIN_MULTI_VAL = [
	'bid',
	'xref',
	'cve',
]

class NessusServer(object):
	def __init__(self, server, port, username, password, verbose=False):
		self.server = server
		self.port = port
		self.username = username
		self.password = password
		self.base_url = 'https://%s:%s' % (self.server, self.port)
		self.verbose = verbose
		self.launched_scans = {}

		# Force urllib2 to not use a proxy
		hand = urllib2.ProxyHandler({})
		opener = urllib2.build_opener(hand)
		urllib2.install_opener(opener)

		self.login()

		# If token file exists, use it
		#self.token = get_token_file()
		#if not self.check_auth():
		#	self.login()
		#	success = create_token_file(self.token)
		#	# if not success...


	def login(self):
		"""Login to server"""
		# If token file exists, try to use it
		self.token = get_token_file()
		if self.check_auth():
			return True

		# Make call to server
		data = make_args(login=self.username, password=quote(self.password))
		resp = self._call('login', data)
		if self.verbose:
			print resp

		# Parse token
		seq, status, parsed = parse_reply(resp, ['token'])
		if 'token' in parsed:
			self.token = parsed['token']
		else:
			return False

		# Store it on the filesystem
		success = create_token_file(self.token)
		if success:
			return True
		else:
			return False

	def logout(self):
		"""Logout from server"""
		data = make_args(token=self.token)
		resp = self._call('logout', data)
		self.token = None

	def check_auth(self):
		"""Does a quick check to make sure token is still valid"""
		if not self.token:
			return False
		data = make_args(token=self.token)
		resp = self._call('scan/list', data)
		if not resp:
			return False
		elif re_unauthorized.search(resp):
			return False
		else:
			return True

	def download_plugins(self):
		"""Downloads all plugins"""
		data = make_args(token=self.token)
		resp = self._call('plugins/descriptions', data)

		# Get parsed data
		keys = []
		seq, status, parsed = parse_reply(resp, keys, uniq='pluginID', start_node='pluginsList')
		return parsed

	def download_report(self, uuid, v1=False):
		"""Retrieves a report"""
		if v1:
			data = make_args(token=self.token, report=uuid, v1='true')
		else:
			data = make_args(token=self.token, report=uuid)
		url = urljoin(self.base_url, 'file/report/download/?%s' % data)
		req = urllib2.urlopen(url) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "Unauthorized"
			return None
		return resp

	def launch_scan(self, name, policy_id, target_list):
		"""Launches scan. Returns UUID of scan."""
		arg_targets = quote('\n'.join(target_list))
		data = make_args(token=self.token, scan_name=quote(name), policy_id=policy_id, target=arg_targets)
		resp = self._call('/scan/new', data)
		if self.verbose:
			print resp

		# Get parsed data
		keys = ['uuid', 'owner', 'start_time', 'scan_name']
		seq, status, parsed = parse_reply(resp, keys)
		self.launched_scans[parsed['uuid']] = parsed
		return parsed['uuid']

	def list_plugins(self):
		"""List plugins"""
		data = make_args(token=self.token)
		resp = _call('plugins/list', data)

	def list_policies(self):
		"""List policies"""
		data = make_args(token=self.token)
		resp = self._call('policy/list', data)

		# Get parsed data
		seq, status, parsed = parse_reply(resp, ['policyName', 'policyOwner', 'policyComments'], uniq='policyID')
		return parsed

	def get_policy_id(self, policy_name):
		"""Attempts to grab the policy ID for a name"""
		pols = self.list_policies()
		for k, v in pols.iteritems():
			if v.get('policyName').lower() == policy_name:
				return k

	def list_reports(self):
		"""List reports"""
		data = make_args(token=self.token)
		resp = self._call('report/list', data)

		# Get parsed data
		seq, status, parsed = parse_reply(resp, ['name', 'readableName', 'timestamp', 'status'], uniq='name')
		return parsed

	def list_scans(self):
		"""List scans"""
		data = make_args(token=self.token)
		resp = self._call('scan/list', data)

		# Get parsed data
		keys = ['owner', 'start_time', 'completion_current', 'completion_total']
		seq, status, parsed = parse_reply(resp, keys, uniq='uuid', start_node='scans/scanList')
		return parsed

	def list_hosts(self, report_uuid):
		"""List hosts for a given report"""
		data = make_args(token=self.token, report=report_uuid)
		resp = self._call('report/hosts', data)

		# Get parsed data
		keys = ['hostname', 'severity']
		seq, status, parsed = parse_reply(resp, keys, uniq='hostname', start_node='hostList')
		return parsed

	def list_ports(self, report_uuid, hostname):
		"""List hosts for a given report"""
		data = make_args(token=self.token, report=report_uuid, hostname=hostname)
		resp = self._call('report/ports', data)
		#return resp

		# Get parsed data
		seq, status, parsed = parse_ports(resp)
		return parsed

	def list_detail(self, report_uuid, hostname, protocol, port):
		"""List details for a given host/protocol/port"""
		data = make_args(token=self.token, report=report_uuid, hostname=hostname, protocol=protocol, port=port)
		resp = self._call('report/detail', data)
		#return resp

		# Get parsed data
		seq, status, parsed = parse_ports(resp)
		return parsed

	def list_tags(self, report_uuid, hostname):
		"""List hosts for a given report"""
		data = make_args(token=self.token, report=report_uuid, hostname=hostname)
		resp = self._call('report/tags', data)
		#return resp

		# Get parsed data
		seq, status, tags = parse_tags(resp)
		return tags

	## Template methods
	def create_template(self, name, policy_id, target_list):
		"""Creates a new scan template. Returns """
		arg_targets = quote('\n'.join(target_list))
		data = make_args(token=self.token, template_name=quote(name), policy_id=policy_id, target=arg_targets)
		resp = self._call('/scan/template/new', data)

	def edit_template(self, template_id, name, policy_id, target_list):
		"""Edits an existing scan template."""
		arg_targets = quote('\n'.join(target_list))
		data = make_args(token=self.token, template=template_id, template_name=quote(name), policy_id=policy_id, target=arg_targets)
		resp = self._call('/scan/template/edit', data)

	def list_templates(self):
		"""List templates"""
		data = make_args(token=self.token)
		resp = self._call('scan/list', data)

		# Get parsed data
		keys = ['policy_id', 'readableName', 'owner', 'startTime']
		seq, status, parsed = parse_reply(resp, keys, uniq='name', start_node='templates')
		return parsed

	def _call(self, func_url, args):
		url = urljoin(self.base_url, func_url)
		if self.verbose:
			print "URL: '%s'" % url
			print "POST: '%s'" % args
		req = urllib2.urlopen(url, args) 
		resp = req.read()
		if not check_auth(resp):
			print >> sys.stderr, "200 Unauthorized"
			return resp
		return resp

def check_auth(resp_str):
	"""Checks for an unauthorized message in HTTP response."""
	if re_unauthorized.search(resp_str):
		return False
	else:
		return True

def create_token_file(token, token_file=TOKEN_FILE):
	"""Creates token file"""
	if not token:
		return False
	# Write to file
	try:
		fout = open(token_file, 'w')
	except IOError:
		return False
	fout.write(token)
	fout.close()

	# Confirm the file was created and has the right token
	new_token = get_token_file(token_file)
	if new_token != token:
		return False
	else:
		return True

def get_token_file(token_file=TOKEN_FILE):
	"""Checks token from file"""
	if not os.path.isfile(token_file):
		return False
	fin = open(token_file, 'r')
	token = fin.read()
	fin.close()
	return token
		
def convert_date(unix_timestamp):
	"""Converts UNIX timestamp to a datetime object"""
	#try:
	#	return datetime.datetime.fromtimestamp(float(unix_timestamp))
	#except Exception:
	#	return unix_timestamp
	return datetime.datetime.fromtimestamp(float(unix_timestamp))

def parse_reply(xml_string, key_list, start_node=None, uniq=None):
	"""Gets all key/value pairs from XML"""
	ROOT_NODES = ['seq', 'status', 'contents']
	if not xml_string:
		return (0, 'Not a valid string', {})

	# Parse xml
	try:
		xml = ET.fromstring(xml_string)
	except ET.ExpatError:
		return (0, 'Cannot parse XML', {})

	# Make sure it looks like what we expect it to be
	if [t.tag for t in xml.getchildren()] != ROOT_NODES:
		return (0, 'XML not formatted correctly', {})

	# Get seq and status
	seq = xml.findtext('seq')
	status = xml.findtext('status')

	# If start node was given, append it to contents node
	if start_node:
		start_node = 'contents/%s' % start_node
	else:
		start_node = 'contents'
	if not xml.find(start_node):
		return (seq, 'start_node not found', {})

	# If a unique value was given, make sure it is a valid tag
	if uniq:
		found = False
		for x in xml.find(start_node).getiterator():
			if x.tag == uniq:
				found = True
				break
		if not found:
			return (seq, 'uniq not a valid tag', {})

	# Parse keys from contents
	d = {}
	for x in xml.find(start_node).getiterator():
		if uniq:
			# If tag is a unique field, start a new dict
			if x.tag == uniq:
				d[x.text] = {}
				k = x.text

			# Store key/value pair if tag is in key list or if no key list was given
			if not x.text:
				continue
			if ((x.tag in key_list) or (not key_list)) and x.text.strip():
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[k][x.tag] = convert_date(x.text)
				else:
					# Check to see if this is multi-valued
					if x.tag in PLUGIN_MULTI_VAL:
						if x.tag in d[k]:
							d[k][x.tag].append(x.text)
						else:
							d[k][x.tag] = [x.text]
					else:
						d[k][x.tag] = x.text

		else:
			# Store key/value pair if tag is in key list
			if not x.text:
				continue
			if ((x.tag in key_list) or (not key_list)) and x.text.strip():
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[x.tag] = convert_date(x.text)
				else:
					d[x.tag] = x.text
	return (seq, status, d)

def parse_reply_orig(xml_string, key_list, start_node=None, uniq=None):
	"""Gets all key/value pairs from XML"""
	ROOT_NODES = ['seq', 'status', 'contents']
	if not xml_string:
		return (0, 'Not a valid string', {})

	# Parse xml
	try:
		xml = ET.fromstring(xml_string)
	except ET.ExpatError:
		return (0, 'Cannot parse XML', {})

	# Make sure it looks like what we expect it to be
	if [t.tag for t in xml.getchildren()] != ROOT_NODES:
		return (0, 'XML not formatted correctly', {})

	# Get seq and status
	seq = xml.findtext('seq')
	status = xml.findtext('status')

	# If start node was given, append it to contents node
	if start_node:
		start_node = 'contents/%s' % start_node
	else:
		start_node = 'contents'
	if not xml.find(start_node):
		return (seq, 'start_node not found', {})

	# If a unique value was given, make sure it is a valid tag
	if uniq:
		found = False
		for x in xml.find(start_node).getiterator():
			if x.tag == uniq:
				found = True
				break
		if not found:
			return (seq, 'uniq not a valid tag', {})

	# Parse keys from contents
	d = {}
	for x in xml.find(start_node).getiterator():
		if uniq:
			# If tag is a unique field, start a new dict
			if x.tag == uniq:
				d[x.text] = {}
				k = x.text

			# Store key/value pair if tag is in key list
			if x.tag in key_list:
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[k][x.tag] = convert_date(x.text)
				else:
					d[k][x.tag] = x.text

		else:
			# Store key/value pair if tag is in key list
			if x.tag in key_list:
				# If the tag has the word time and the value is a UNIX timestamp, convert it
				if 'time' in x.tag and re_unix_timestamp.search(x.text):
					d[x.tag] = convert_date(x.text)
				else:
					d[x.tag] = x.text
	return (seq, status, d)

def parse_ports(xml_string):
	"""Parses ports from report/ports"""
	ROOT_NODES = ['seq', 'status', 'contents']
	if not xml_string:
		return (0, 'Not a valid string', {})

	# Parse xml
	try:
		xml = ET.fromstring(xml_string)
	except ET.ExpatError:
		return (0, 'Cannot parse XML', {})

	# Make sure it looks like what we expect it to be
	if [t.tag for t in xml.getchildren()] != ROOT_NODES:
		return (0, 'XML not formatted correctly', {})

	# Get seq and status
	seq = xml.findtext('seq')
	status = xml.findtext('status')

	# Parse ports
	d = {'tcp': {}, 'udp': {}, 'icmp': {}}
	for t in xml.findall('contents/portList/port'):
		port_d = {}
		prot = t.findtext('protocol')
		num = t.findtext('portNum')

		# Get additional attributes
		port_d['severity'] = t.findtext('severity')
		port_d['svcName'] = t.findtext('svcName')

		d[prot][num] = port_d
	return (seq, status, d)

def parse_tags(xml_string):
	"""Parses tags from report/tags"""
	ROOT_NODES = ['seq', 'status', 'contents']
	if not xml_string:
		return (0, 'Not a valid string', {})

	# Parse xml
	try:
		xml = ET.fromstring(xml_string)
	except ET.ExpatError:
		return (0, 'Cannot parse XML', {})

	# Make sure it looks like what we expect it to be
	if [t.tag for t in xml.getchildren()] != ROOT_NODES:
		return (0, 'XML not formatted correctly', {})

	# Get seq and status
	seq = xml.findtext('seq')
	status = xml.findtext('status')

	# Parse tags
	d = {}
	for t in xml.findall('contents/tags/tag'):
		k = t.findtext('name')
		v = t.findtext('value')
		d[k] = v
	return (seq, status, d)

def make_args(**kwargs):
	"""Returns arg list suitable for GET or POST requests"""
	args = []
	for k in kwargs:
		args.append('%s=%s' % (k, str(kwargs[k])))

	# Add a random number
	seq = randint(1, 1000)
	args.append('seq=%d' % seq)
	
	return '&'.join(args)

def zerome(string):
	# taken from http://www.codexon.com/posts/clearing-passwords-in-memory-with-python
	# to be used to secure the password in memory
	# find the header size with a dummy string
	temp = "finding offset"
	header = ctypes.string_at(id(temp), sys.getsizeof(temp)).find(temp)
 
	location = id(string) + header
	size = sys.getsizeof(string) - header
 
	# Check platform
	if 'windows' in sys.platform.lower():
		memset = ctypes.cdll.msvcrt.memset
	else:
		# For Linux, use the following. Change the 6 to whatever it is on your computer.
		memset = ctypes.CDLL("libc.so.6").memset
 
	print "Clearing 0x%08x size %i bytes" % (location, size)
 
	memset(location, 0, size)
