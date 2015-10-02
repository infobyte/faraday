# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v1.2
# Released under GPL Version 2 license.
#
# See the INSTALL file for installation instructions.
# 
# For more information contact us at carbonator at integrissecurity dot com
# Or visit us at https://www.integrissecurity.com/
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerListener
from java.net import URL
from java.io import File

import time

class BurpExtender(IBurpExtender, IHttpListener, IScannerListener):
    def registerExtenderCallbacks(self, callbacks):
	self._callbacks = callbacks
	self._callbacks.setExtensionName("Carbonator")
	self._helpers = self._callbacks.getHelpers()
	self.clivars = None

	self.spider_results=[]
	self.scanner_results=[]
	self.packet_timeout=5

	self.last_packet_seen= int(time.time()) #initialize the start of the spider/scan

	if not self.processCLI():
		return None
	else:
		self.clivars = True

	print "Initiating Carbonator Against: ", str(self.url)
	#add to scope if not already in there.
	if self._callbacks.isInScope(self.url) == 0:
		self._callbacks.includeInScope(self.url)

	#added to ensure that the root directory is scanned
	base_request = str.encode(str("GET "+self.path+" HTTP/1.1\nHost: "+self.fqdn+"\n\n"))
	if(self.scheme == 'HTTPS'):
		print self._callbacks.doActiveScan(self.fqdn,self.port,1,base_request)
	else:
		print self._callbacks.doActiveScan(self.fqdn,self.port,0,base_request)

	self._callbacks.sendToSpider(self.url)
	self._callbacks.registerHttpListener(self)
	self._callbacks.registerScannerListener(self)

	while int(time.time())-self.last_packet_seen <= self.packet_timeout:
		time.sleep(1)
	print "No packets seen in the last", self.packet_timeout, "seconds."
	print "Removing Listeners"
	self._callbacks.removeHttpListener(self)
	self._callbacks.removeScannerListener(self)
	self._callbacks.excludeFromScope(self.url)

	print "Generating Report"
	self.generateReport(self.rtype)
	print "Report Generated"
	print "Closing Burp in", self.packet_timeout, "seconds."
	time.sleep(self.packet_timeout)

	if self.clivars:
		self._callbacks.exitSuite(False)
		
	return

    def processHttpMessage(self, tool_flag, isRequest, current):
	self.last_packet_seen = int(time.time())
	if tool_flag == self._callbacks.TOOL_SPIDER and isRequest: #if is a spider request then send to scanner
		self.spider_results.append(current)
		print "Sending new URL to Vulnerability Scanner: URL #",len(self.spider_results)
		if self.scheme == 'https':
			self._callbacks.doActiveScan(self.fqdn,self.port,1,current.getRequest()) #returns scan queue, push to array
		else:
			self._callbacks.doActiveScan(self.fqdn,self.port,0,current.getRequest()) #returns scan queue, push to array
	return

    def newScanIssue(self, issue):
	self.scanner_results.append(issue)
	print "New issue identified: Issue #",len(self.scanner_results);
	return

    def generateReport(self, format):
	if format != 'XML':
		format = 'HTML'	

	file_name = self.output
	self._callbacks.generateScanReport(format,self.scanner_results,File(file_name))	

	time.sleep(5)
	return

    def processCLI(self):
	cli = self._callbacks.getCommandLineArguments()
	if len(cli) < 0:
		print "Incomplete target information provided."
		return False
	elif not cli:
		print "Integris Security Carbonator is now loaded."
		print "If Carbonator was loaded through the BApp store then you can run in headless mode simply adding the `-Djava.awt.headless=true` flag from within your shell. Note: If burp doesn't close at the conclusion of a scan then disable Automatic Backup on Exit."
		print "For questions or feature requests contact us at carbonator at integris security dot com."
		print "Visit carbonator at https://www.integrissecurity.com/Carbonator"
		return False
	else:
		self.url = URL(cli[0])
		self.rtype = cli[1] 
		self.output = cli[2]

		self.scheme = self.url.getProtocol()
		self.fqdn = self.url.getHost()
		self.port1 = self.url.getPort()
		if self.port1 == -1 and self.scheme == 'http':
			self.port = 80
		elif self.port1 == -1 and self.scheme == 'https':
			self.port = 443
		else:
			self.port = self.port1
		self.path = self.url.getFile()
		print "self.url: " + str(self.url) + "\n"
		print "Scheme: " + self.scheme + "\n"
		print "FQDN: " + self.fqdn + "\n"
		print "Port: " + str(self.port1) + "\n"
		print "Path: " + self.path + "\n"
	return True
