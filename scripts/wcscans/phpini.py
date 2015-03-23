'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from lxml import etree as ET	

VRAI = ['yes','on','1']
FAUX = ['no','off','0']

def equals(value1,value2):
	if (value1.lower() in VRAI and value2.lower() in VRAI) or	(value1.lower() in FAUX and value2.lower() in FAUX):
		return True 
	else:
		return False	
	
#Good practices
rules = {
		'session.use_cookies':['Cookies for sessions are disabled','1'],
		'session.use_only_cookies':['Only cookies for sessions is disabled','1'],
		'session.cookie_httponly':['Cookies are not set to HTTP only','1'],
		'session.bug_compat_42':['Bug compatibility 42 is enabled','0'],
		'session.bug_compat_warn':['Bug compatibility 42 warning is enabled','0'],
		'session.use_trans_sid':['Use of \'use_trans_sid\' is considered harmful','0'],
		'session.cookie_secure':['Cookie is not set to secure connection','1'],
		'session.use_strict_mode':['Strict mode is disabled for session fixation prevention','1'],
		'session.cookie_domain':['Cookie domain is not set',''],
		'session.hash_function':['Weak session id generation: a stronger hash function such as SHA256 should be used',''],
		'allow_url_fopen':['Remote file opening is allowed','off'],
		'allow_url_include':['Remote file including is allowed','off'],
		'error_reporting':['Errors reports are enabled in production','0'],
		'display_errors':['Errors should not be shown in production','off'],
		'log_errors':['Log errors are not written in production','on'],
		'expose_php':['PHP signature should disabled','off'],
		'register_globals':['Register globals is enabled','off'],
		'magic_quotes_gpc':['Magic quotes is enabled','off'],
		'magic_quotes_runtime':['Magic quotes is enabled at runtime','off'],
		'safe_mode':['Safe mode is enabled','off'],
		'register_long_arrays':['Register long arrays is enabled','off'],
		'display_startup_errors':['Startup errors is displayed','off'],
		'max_input_vars':['Maximum input variables is not set',''],
		'open_basedir':['You should restrict PHP\'s file system access (basedir)',''],
		'memory_limit':['You should define a reasonable memory limit (<128 M)',''],
		'post_max_size':['You should define a reasonable max post size ',''],
		'upload_max_filesize':['You should define a reasonable max upload size',''],
		'upload_tmp_dir':['You should define a temporary directory used for file uploads',''],
		'asp_tags':['ASP tag handling is not turned off','0'],
		'xdebug.default_enable':['Xdebug is enabled','0'],
		'xdebug.remote_enable':['Xdebug should not be trying to contact debug clients','0'],
		}	

#Lines of config whose default values are bad
bad_default_config = ['session.cookie_httponly','session.bug_compat_42',
                    'session.bug_compat_warn','allow_url_fopen',
										'error_reporting','display_errors','log_errors',
                    'expose_php','magic_quotes_gpc','register_long_arrays']

#Lines of config that is not set (value by the user)
is_set_config = ['max_input_vars','open_basedir', 'memory_limit','post_max_size',
                 'upload_max_filesize','upload_tmp_dir']

#Weak hashing functions
weak_functions = ['md2', 'md4', 'md5', 'sha1', 'gost', 'snefru', '0', '1']
		
#To-be-disabled functions
weak_php_functions = ['passthru', 'shell_exec', 'exec', 
                      'system', 'popen', 'stream_select']
	

class PhpIniScan:

	def __init__(self, file, xml):
		self.config = ""
		for line in open(file,"r"):
			if not re.match(r'(^(;|\[))',line,) and line[0] != '\n':
				self.config += line.lstrip()
		self.recommended = "\nRecommended configuration changes in php.ini:\n"
		self.xml = xml	
	
	def xml_export(self,directive,rec):
		if self.xml is not None:
			newElement = ET.SubElement(self.xml, directive[0])
			newElement.attrib['rec'] =  rec
			newElement.text = directive[1]
			
	def global_check(self):
		print "[+]\033[0;41mVulnerabilites/Informations\033[0m:"
		for line in self.config.split('\n'):
			directive = ''.join(line.split()).split('=')
	
			if ( rules.has_key(directive[0]) and not equals(rules[directive[0]][1],directive[1])) or directive[0] in bad_default_config:
				print "   \033[1;30m({})\033[0m {}".format(directive[0],rules[directive[0]][0])
				self.recommended += "   {} = {}\n".format(directive[0],rules[directive[0]][1])
				self.xml_export(directive,rules[directive[0]][0])
				continue
				
			if rules.has_key(directive[0]) and directive[1] == "": 
				print "   \033[1;30m({})\033[0m {}".format(directive[0],rules[directive[0]][0])
				self.recommended += "   {} = {}\n".format(directive[0],rules[directive[0]][1])	
				self.xml_export(directive,rules[directive[0]][0])
				continue	
				
			if directive[0] == "session.hash_function" and directive[1] in weak_functions:
				print "   \033[1;30m({})\033[0m {}".format(directive[0],rules[directive[0]][0])
				self.recommended += "   {} = sha256\n".format(directive[0])
				self.xml_export(directive,rules[directive[0]][0])
				continue
			
			if directive[0] == "disable_functions":
				for option in weak_php_functions:
					if not option in directive[1]:
						print "   \033[1;30m(disable_functions)\033[0m {} not listed".format(option)
						self.recommended += "   disable_functions = ... , {} , ...\n".format(option)
				self.xml_export(directive,"")
				continue
				
		for element in is_set_config:
			if not element in self.config:
				print "   \033[1;30m({})\033[0m {}".format(element,rules[element][0]) 
				self.recommended += "   {} is not set\n".format(element)
				directive = [element,'isNotSet']
				self.xml_export(directive,rules[directive[0]][0])
				
		for element in bad_default_config:
			if not element in self.config:
				print "   \033[1;30m({})\033[0m {}".format(element,rules[element][0]) 
				self.recommended += "   {} = {}\n".format(element,rules[element][1])
				directive = [element,'defaultValue']
				self.xml_export(directive,rules[directive[0]][0])
				
			# TODO Session save path not set or world writeable		 || CheckSessionPath
			# TODO Entropy file is not defined					 || CheckSessionEntropyPath
			# TODO Maximum post size too large					     || MaximumPostSize
			# TODO Disable harmful CLI functions					 || DisableCliFunctions
			# TODO CVE-2013-1635									 ||	CheckSoapWsdlCacheDir
			# TODO Ensure file uploads workCheck				     || UploadTmpDir
			# TODO check the sizes (in M) f some parameters)

def scanner(file,recmode,xml):
	filetoscan = PhpIniScan(file,xml)
	filetoscan.global_check()
	if recmode:
		print filetoscan.recommended
