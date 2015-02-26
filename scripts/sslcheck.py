#!/usr/bin/python2	
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

#libraries
import subprocess								
import argparse 									
import re																		
import sys											
import xml.etree.cElementTree as ET		

if subprocess.call("openssl version", shell=True, stdout=subprocess.PIPE):
	sys.stderr.write("[+]OpenSSL package needed\n")
	exit(1)

program_options = ('key', 'ren', 'sign', 'serv', 'cyph', 'forw', 'heart', 'crime', 'all')  
openssl_protocols = {'ssl3':'SSLv3', 
					'tls1':'TLSv1', 
					'tls1_1':'TLSv1.1',
					'tls1_2':'TLSv1.2'} 
openssl_insecure_cyphers = {'RC','MD5','MD4','MD2','SHA0','SHA1', 'NULL','aNULL',
							'eNULL','ADH','EXP','DES','LOW','PSK','SRP','DSS'}
openssl_cyphers = subprocess.check_output("openssl ciphers 'ALL:eNULL'",shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE).split(":")

parser = argparse.ArgumentParser(prog='SensorProbeClient', epilog="Scan availables: | KeySize: key | Signature Cipher: sign |Renegotiation: ren | Services available: serv | Cypher availables: cyph | Forward Secrecy: forw | Heartbleed test: heart | Crime test: crime")
parser.add_argument('-r', action="store", type=str, choices=program_options, dest='choice', default="all", nargs='+', help='store the scan(s) requested by the users')
parser.add_argument('-port', '--port', action="store", type=int, dest='port', default="443", help='store the port to scan')
parser.add_argument('--xml', action='store', type=str, dest='xmloutput', help='enabled the XML output in a specified file')
parser.add_argument('host', nargs='+', type=str, help='store the target\'s host address (domain name or ipv4) separated by a space')
parser.add_argument('--version', "-v", action='version', version='%(prog)s v1.0 by Morgan Lemarechal')

args = parser.parse_args()

def connection_test(host,port):
	for i in range(1,6):
		try:
			subprocess.check_output("openssl s_client -connect {}:{} < /dev/null".format(host,port), shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
			return
		except subprocess.CalledProcessError: 
			print "[+]Connection failed... [ {} / 5 ]".format(i)
	print "[+]Connection to the host impossible"
	exit(1)
		
def basic_connect(host,port):
	result = subprocess.check_output("openssl s_client -connect {}:{} < /dev/null".format(host,port), shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)	
	return result.split("\n")
	
def complex_connect(host,port):
	result = "" 
	for sprotocol, protocol in openssl_protocols.iteritems():
		try:
			result += subprocess.check_output("openssl s_client -{} -connect {}:{} < /dev/null".format(sprotocol,host,port),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
		except subprocess.CalledProcessError:
		#-----------------------------------XML_Export-----------------------------------#
			if args.xmloutput:
				protocolx = ET.SubElement(scan, protocol)
				protocolx.text="no"
		#-----------------------------------XML_Export-----------------------------------#		
			if protocol == "TLSv1.1" or protocol == "TLSv1.2":
				print "   \033[0;41m{} not supported\033[0m".format(protocol)
			else:
				print "   {} not supported".format(protocol)
	return result.split("\n")		
def tlsdebug_connect(host,port):
	result = subprocess.check_output("openssl s_client -tlsextdebug -connect {}:{} < /dev/null".format(host,port),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)	
	return result.split("\n")
	
def sign_connect(host,port):
	signScript = """
	echo "HEAD / HTTP/1.0
	EOT
	" \
	| openssl s_client -connect {}:{} 2>&1 \
	| sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
	| openssl x509 -noout -text -certopt no_signame""".format(host,port)
	result = subprocess.check_output("{}".format(signScript),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)	
	return result.split("\n")
	
def cypher_connect(host,port):
	result = ""
	for cyph in openssl_cyphers:
		try:
			result += subprocess.check_output("openssl s_client -cipher {} -connect {}:{} < /dev/null".format(cyph,host,port),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
		except subprocess.CalledProcessError:
			pass
	return result.split("\n")
	
def forward_connect(host,port):
	result = ""
	try:
		result = subprocess.check_output("openssl s_client -cipher EDH,EECDH -connect {}:{} < /dev/null".format(host,port),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
	except subprocess.CalledProcessError:
	#-----------------------------------XML_Export-----------------------------------#
		if args.xmloutput:
			forward_secrecy = ET.SubElement(scan, "forward_secrecy")
			forward_secrecy.text="no"
	#-----------------------------------XML_Export-----------------------------------#		
		print "\033[0;41m[+]Forward Secrecy not supported\033[0m"
	return result.split("\n")
	
def key_check(host,port):
	for line in basic_connect(host,port):
		if "Server public key is" in line:
		#-----------------------------------XML_Export-----------------------------------#
			if args.xmloutput:
				key_size  = ET.SubElement(scan, "key")
				key_size.text = str(re.findall(r'\d+', line)[0])
		#-----------------------------------XML_Export-----------------------------------#		
			print "[+]{}\n".format(line),
			if int(re.findall(r'\d+', line)[0]) < 2048:
				print ("\033[0;41m[+]Insecure key size, it must be higher than 2048 bits\033[0m")
			return	
					
def ren_check(host,port):
	for line in basic_connect(host,port):
		if "Secure Renegotiation" in line:
			if "IS NOT supported" in line:
			#-----------------------------------XML_Export-----------------------------------#
				if args.xmloutput:
					renegotiation = ET.SubElement(scan, "renegotiation")
					renegotiation.text="no"
			#-----------------------------------XML_Export-----------------------------------#
				print "\033[0;41m[+]Secure renegotiation not supported\033[0m"
			else:
			#-----------------------------------XML_Export-----------------------------------#
				if args.xmloutput:
					renegotiation = ET.SubElement(scan, "renegotiation")
					renegotiation.text="yes"
			#-----------------------------------XML_Export-----------------------------------#		
				print "[+]"+line
			return		
		

def sign_check(host,port):
	for line in sign_connect(host,port):
		if "Signature Algorithm" in line:	
			insecure = False
			for insecure_cypher in openssl_insecure_cyphers:	
				if insecure_cypher in line or insecure_cypher.upper() in line or insecure_cypher.lower() in line:
					insecure = True 
					print "\033[0;41m[+]{}\033[0m\n".format(line.replace("    ","")),
					#-----------------------------------XML_Export-----------------------------------#	
					if args.xmloutput:			
						signature_cipher = ET.SubElement(scan, line.replace("    Signature Algorithm: ",""))
						signature_cipher.text = "signature insecure"
					#-----------------------------------XML_Export-----------------------------------#	
					break
			if not insecure:
				#-----------------------------------XML_Export-----------------------------------#	
				if args.xmloutput:	
					signature_cipher = ET.SubElement(scan, line.replace("    Signature Algorithm: ",""))
					signature_cipher.text = "signature secure"
				#-----------------------------------XML_Export-----------------------------------#
				print "[+]"+line.replace("    ","") 
		
def serv_check(host,port):	
	print "[+]Protocols supported by the server:"
	for line in complex_connect(host,port):
		for i,protocol in enumerate(openssl_protocols):
			if line.endswith(openssl_protocols[protocol]):	
				if openssl_protocols[protocol] == "SSLv3" or openssl_protocols[protocol] == "TLSv1":
					print "   \033[0;41m"+openssl_protocols[protocol],
				else:
					print "   "+openssl_protocols[protocol],	
			#-----------------------------------XML_Export-----------------------------------#
				if args.xmloutput:
					protocolx = ET.SubElement(scan, openssl_protocols[protocol])
					protocolx.text="yes"
			#-----------------------------------XML_Export-----------------------------------#			
		if "Cipher    " in line:
			print "|| Default cipher:{}\033[0m".format(line.replace("   Cipher    : ","").replace("0000",""))
			
def cyph_check(host,port):		
	print "[+]Ciphers supported by the server (it may takes a minute):"
	for line in cypher_connect(host,port):
		if "Cipher    : " in line: 
			insecure = False
			for insecure_cypher in openssl_insecure_cyphers:
				if insecure_cypher in line or insecure_cypher.upper() in line or insecure_cypher.lower() in line:
				#-----------------------------------XML_Export-----------------------------------#
					if args.xmloutput:
						cypher = ET.SubElement(scan, line.replace("    Cipher    : ",""))
						cypher.text = "insecure"
				#-----------------------------------XML_Export-----------------------------------#					
					print "   \033[0;41m{}\033[0m\n".format(line.replace("    Cipher    : ","Supported cipher suite: [INSECURE] ")),
					insecure = True 
					break
			if not insecure:
			#-----------------------------------XML_Export-----------------------------------#
				if args.xmloutput:
					cypher = ET.SubElement(scan, line.replace("    Cipher    : ",""))
					cypher.text = "secure"
			#-----------------------------------XML_Export-----------------------------------#			
				print line.replace("    Cipher    : ","   Supported cipher suite: [SECURE] ")

def forw_check(host,port):
	for line in forward_connect(host,port):
		if "Cipher    : " in line: 
		#-----------------------------------XML_Export-----------------------------------#	
			if args.xmloutput:
				forward_secrecy = ET.SubElement(scan, "forward_secrecy")
				forward_secrecy.text="yes"
		#-----------------------------------XML_Export-----------------------------------#		
			print "[+]{} (prefered)".format(line.replace("    Cipher    : ","Forward Secrecy supported: "))
			return
	
def heart_check(host,port):
	for line in tlsdebug_connect(host,port):
		if "TLS server extension heartbeat" in line :
		#-----------------------------------XML_Export-----------------------------------#
			if args.xmloutput:
				heartbeat = ET.SubElement(scan, "heartbeat")
				heartbeat.text = "yes"	
		#-----------------------------------XML_Export-----------------------------------#		
			print "\033[0;41m[+]Heartbeat extension vulnerable\033[0m"
			return;
#-----------------------------------XML_Export-----------------------------------#
	if args.xmloutput:
		heartbeat = ET.SubElement(scan, "heartbeat")
		heartbeat.text = "no"		
#-----------------------------------XML_Export-----------------------------------#		
	print "[+]Heartbeat extension disabled"		
		
def crime_check(host,port):
	for line in basic_connect(host,port):
		if "Compression: NONE" in line:
		#-----------------------------------XML_Export-----------------------------------#
			if args.xmloutput:
				crime = ET.SubElement(scan, "crime")
				crime.text = "no"	
		#-----------------------------------XML_Export-----------------------------------#
			print "[+]Compression disabled, CRIME is prevented"
			return
		elif "Compression: " in line: 
		#-----------------------------------XML_Export-----------------------------------#
			if args.xmloutput:
				crime = ET.SubElement(scan, "crime")
				crime.text = "yes"	
		#-----------------------------------XML_Export-----------------------------------#
			print ("\033[0;41m[+]Potentially vulnerable to CRIME:{}\033[0m").format(line)
			return			
			
print """\n\033[0;33m
 ___ ___ _    ___ _           _  
/ __/ __| |  / __| |_  ___ __| |_ 
\__ \__ \ |_| (__| ' \/ -_) _| / /
|___/___/____\___|_||_\___\__|_\_\ \033[0m

   Version v1.0: November 2014
	Morgan Lemarechal\n"""

if args.xmloutput:
	root = ET.Element("sslcheck")
	
for host in args.host:
	
	if  re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",host):
			host_ip = host
			host_name = ""
			#host_name = subprocess.check_output("dig -x {} +short|sed 's/\.$//g'".format(host),shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE).rstrip()
			print "[+]Perfoming the scan of {}".format(host_ip)	
	else:
			host_name = host
			host_ip = subprocess.check_output("nslookup "+host+" | tail -2 | head -1|awk '{print $2}'",shell=True, stdin=subprocess.PIPE, stderr=subprocess.PIPE).rstrip()
			print "[+]Perfoming the scan of {}|{}".format(host_name,host_ip)	
	
	try:
	#-----------------------------------XML_Export-----------------------------------#
		if args.xmloutput:
			scan = ET.SubElement(root, "scan")
			scan.set('host',host_ip) 
			scan.set('port',str(args.port))
			scan.set('hostname',host_name)
	#-----------------------------------XML_Export-----------------------------------#		
		connection_test(host,args.port)
		for scanning in program_options:
			if args.choice == "all" or scanning in args.choice:
				if not scanning == "all":
					action = scanning+"_check"
					globals()[action](host,args.port)
		
	except KeyboardInterrupt:		
		print "[+]Interrupting SSLcheck..."
		exit(1)
	
#-----------------------------------XML_Export-----------------------------------#				
if args.xmloutput:
	tree = ET.ElementTree(root)
	try:
		fo = open(args.xmloutput, "w")
		tree.write(fo) 
		fo.close()
	except IOError:
		sys.exit('\033[0;41m[+]XML export failed.\033[0m')
#-----------------------------------XML_Export-----------------------------------#	
