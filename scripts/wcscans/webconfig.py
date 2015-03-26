'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lxml import etree as ET

rules = {
        'compilation':{'debug':['ASP.NET Debugging enabled',
                                                        'false']},
        'customErrors':{'mode':['Custom Errors disabled',
                                                        'on remoteonly']},
        'forms':{'cookieless':['Cookieless authentication Enabled for form',
                                                     'usecookies'],
        'requireSSL':['SSL connection is not required',
                                 'true'],
        'slidingExpiration':['Sliding expiration enabled',
                                                'false'],
        'enableCrossAppRedirects':['URL Redirection enabled',
                                                            'false'],
        'protection':['The cookies are only encrypted or only validated or not protected',
                                    'all']},
        'httpCookies':{'httpOnlyCookies':['Web cookies are not HttpOnly',
                                                                            'true'],
        'requireSSL':['Web cookies don\'t require SSL',
                                 'true']},
        'pages':{'enableViewState':['ViewState is enabled (CRSF vulnerability)',
                                                                'true'],
        'enableViewStateMac':['ViewState integrity is not checked',
                                                 'true'],
        'viewStateEncryptionMode':['ViewState may not be encrypted',
                                                            'always'],
        'validateRequest':['Page Validation is not used (XSS vulnerability)',
                                            'true']},
        'roleManager':{'cookieRequireSSL':['Cookies don\'t Require SSL',
                                                                            'true'],
        'cookieSlidingExpiration':['Sliding expiration enabled',
                                                            'false'],
        'cookieProtection':['The cookies are only encrypted or only validated or not protected',
                                             'all'],
        'cookiePath':['Liberal path defined','']},
        'sessionState':{'cookieless':['Cookieless session stated enabled',
                                                                    'usecookies']},
        'trace':{'enabled':['Trace is enabled',
                                                'false'],
        'localOnly':['Trace localOnly on false',
                                'true']},
        'trust':{'level':['Web application\'s trust level is higher than Minimal',
                                            'minimal']},
        'user':{'':['Passwords (or its hashes) are hardcoded','']}
        }

class WebConfigScan:

    def __init__(self, file, xml):
        tree = ET.parse(file)
        self.root = tree.getroot()
        self.recommended = "\nRecommended configuration changes in web.config:\n"
        self.xml = xml
        
    def xml_export(self,directive,rec):
        if self.xml is not None: 
            newElement = ET.SubElement(self.xml, directive[0])
            if len(directive) == 4:
                newElement.attrib['name'] = directive[3]
            newElement.attrib['option'] = directive[1]
            newElement.attrib['rec'] = rec
            newElement.text = directive[2]
        
            
    def global_check(self):
        print "[+]\033[0;41mVulnerabilites/Informations\033[0m:"
        countforms = 0
        nameforms = []
        for element in rules:
            for tag in self.root.findall(".//"+element):
                if element == "forms":
                    countforms += 1
                    nameforms.append(tag.attrib['name'])
                if element == "user":   
                    print "   \033[1;30m{}\033[0m {}: {} \033[1;30m({})\033[0m".format(element,
                                                                                    tag.attrib['name'],
                                                                                    rules[element][''][0],
                                                                                    option)         
                    self.recommended += "   Not to store passwords or hashes in web.config\n"
                    self.xml_export(directive=[element, tag.attrib['name'],'hardcoded'],
                                                    rec=rules[element][''][0])
                    continue
                    
                for option in tag.attrib: 
                    if element == "customErrors" and rules[element].has_key(option) and not tag.attrib[option].lower() in rules[element][option][1]:
                        print "   \033[1;30m{}\033[0m: {} \033[1;30m({})\033[0m".format(element,
                                                                                        rules[element][option][0],
                                                                                        option)                                                                                                                                 
                        self.recommended += "   <{} {}=\"{}\"/>\n".format(element,option,rules[element][option][1])
                        self.xml_export(directive=[element,option,'disabled'],
                                                        rec=rules[element][option][0])
                        continue
                        
                    elif element == "roleManager" and option == "cookiePath":
                        print "   \033[1;30mroleManager\033[0m: Liberal path defined ('{}') (\033[1;30mcookiePath\033[0m)".format(tag.attrib[option].lower())
                        self.recommended += "   <roleManager cookiePath=\"{abcd1234…}\">\n"
                        self.xml_export(directive=[element,option,'liberal'],
                                                        rec=rules[element][option][0])
                        continue
                    
                    if rules[element].has_key(option) and tag.attrib[option].lower() != rules[element][option][1]:
                        if element == "forms":
                            print "   \033[1;30m{}\033[0m {}: {} \033[1;30m({})\033[0m".format(element,
                                                                                               tag.attrib['name'],
                                                                                               rules[element][option][0],
                                                                                               option)          
                            self.xml_export(directive=[element,option,tag.attrib[option],tag.attrib['name']],
                                                            rec=rules[element][option][0])                                                                   
                            
                        else:
                            print "   \033[1;30m{}\033[0m: {} \033[1;30m({})\033[0m".format(element,
                                                                                            rules[element][option][0],
                                                                                            option)
                                                                                            
                            self.xml_export(directive=[element,option,tag.attrib[option]],
                                                            rec=rules[element][option][0])                                                                      
                        self.recommended += "   <{} {}=\"{}\"/>\n".format(element,option,rules[element][option][1])
                        continue
                    
        if countforms > 1 and (nameforms.index('.ASPXAUTH') != "-1" or nameforms.index('ASPXAUTH') != "-1"):
            print "   \033[1;30mforms\033[0m: Non-Unique authentication cookie used\033[1;30m (name)\033[0m"
            self.recommended += "   <forms name=\"{abcd1234…}\">\n"
            self.xml_export(directive=['nameforms','name','false'],
                                            rec="Non-Unique authentication cookie used")
            
def scanner(file,recmode,xml):
    filetoscan = WebConfigScan(file,xml)
    filetoscan.global_check()
    if recmode:
        print filetoscan.recommended
    
