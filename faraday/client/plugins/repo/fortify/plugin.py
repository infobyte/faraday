import io
import re
import string
import ntpath
import random
import string
from HTMLParser import HTMLParser
from zipfile import ZipFile
from lxml import objectify, etree
from faraday.client.plugins import core


class FortifyPlugin(core.PluginBase):
    """
    Example plugin to parse nmap output.
    """
    def __init__(self):
        core.PluginBase.__init__(self)
        self.id = "Fortify"
        self.name = "Fortify XML Output Plugin"
        self.plugin_version = "0.0.1"

    def parseOutputString(self, output, debug=False):
        fp = FortifyParser(output)

        for host in fp.hosts.keys():
            fp.hosts[host] = self.createAndAddHost(host)

        for vuln in fp.vulns.keys():
            self.createAndAddVulnToHost(    
                host_id=fp.hosts[fp.vulns[vuln]['host']],
                name=fp.vulns[vuln]['name'],
                desc=fp.format_description(vuln),
                ref=fp.descriptions[fp.vulns[vuln]['class']]['references'],
                severity=fp.vulns[vuln]['severity'], 
                resolution="", 
                data="", 
                external_id=vuln.text
                )
        
        return True


class FortifyParser():
    """  
    Parser for fortify on demand
    """
    def __init__(self, output):
        self.vulns = {}
        self.hosts = {}
        self.fvdl = None
        self.audit = None
        self.suppressed = []
        self.vuln_classes = []
        self.descriptions = {}

        self._uncompress_fpr(output)
        self._extract_vulns()
        self._prepare_description_templates()

        #regexes used in format_description
        self.remove_extra_chars = re.compile(r'&amp;(\w*);')
        self.replacements_idx = re.compile(r'<Replace key="(.*?)"[\s\/].*?>')
        self.replacements_holders = re.compile(r'<Replace key=".*?"[\s\/].*?>')
        self.replacements_idx2 = re.compile(r'<Replace key="(.*?)"(\slink="(.*?)")?[\s\/].*?>')


    def _uncompress_fpr(self, output):
        with ZipFile(io.BytesIO(output)) as fprcontent:
            self.fvdl = objectify.fromstring(fprcontent.read('audit.fvdl'))
            self.audit = objectify.fromstring(fprcontent.read('audit.xml'))

    def _extract_vulns(self):
        #make list of false positives
        for issue in self.audit.IssueList.iterchildren():
            if issue.get('suppressed') == 'true':
                self.suppressed.append(issue.get('instanceId'))

        for vuln in self.fvdl.Vulnerabilities.iterchildren():

            vulnID = vuln.InstanceInfo.InstanceID
            
            if vulnID in self.suppressed:
                continue

            self.vulns[vulnID] = {}

            # the last children of Primary (Entry tags) always contains vuln filename ,path and line
            _last_entry = None
            for _last_entry in vuln.AnalysisInfo.Unified.Trace.Primary.iterchildren():
                pass

            path = _last_entry.Node.SourceLocation.get('path')

            self.vulns[vulnID]['host'] = path
            self.vulns[vulnID]['name'] = "{} {}".format(vuln.ClassInfo.Type, 
                                                        getattr(vuln.ClassInfo, "Subtype", ""))
            self.vulns[vulnID]['class'] = vuln.ClassInfo.ClassID
            self.vulns[vulnID]['replacements'] = {}
            
            self.vulns[vulnID]['severity'] = self.calculate_severity(vuln)

            #placeholder for storing hosts ids when created in main plugin method                    
            if path not in self.hosts.keys():
                self.hosts[path] = None

            if vuln.ClassInfo.ClassID not in self.vuln_classes:
                self.vuln_classes.append(vuln.ClassInfo.ClassID)

            # fortify bug that when it has no replacements, shows blank in fortify dashboard
            if not hasattr(vuln.AnalysisInfo.Unified, "ReplacementDefinitions"):
                self.vulns[vulnID]['replacements'] = None
                continue

            try:
                getattr(vuln.AnalysisInfo.Unified, "ReplacementDefinitions") 

                for repl in vuln.AnalysisInfo.Unified.ReplacementDefinitions.iterchildren(
                    tag="{xmlns://www.fortifysoftware.com/schema/fvdl}Def"):

                    repl_val = repl.get('key') 
                    if repl.get('link'):
                        repl_val = repl.get('link')

                    self.vulns[vulnID]['replacements'][repl_val] = repl.get('value')
            except AttributeError:
                self.vulns[vulnID]['replacements'] = None


    def calculate_severity(self, vuln):

        severity = None #["critical", "high", "medium", "low", "informational", "unclassified"]
        rulepath = objectify.ObjectPath("FVDL.EngineData.RuleInfo.Rule")
        likelihood = None
        impact = None
        probability = None
        accuracy = None

        #XML path /FVDL/EngineData/RuleInfo/Rule (many)/MetaInfo/Group (many) the attribute "name"
        #are keys for vuln properties 

        for rule in rulepath(self.fvdl):
            if rule.get('id') == vuln.ClassInfo.ClassID:
                for group in rule.MetaInfo.iterchildren():
                    if group.get('name') == "Probability":
                        probability = group
                    if group.get('name') == "Impact":
                        impact = group
                    if group.get('name') == "Accuracy":
                        accuracy = group

        likelihood = (accuracy * vuln.InstanceInfo.Confidence * probability) / 25        

        if impact and probability:

            if impact >= 2.5 and likelihood >= 2.5:
                severity = 'critical'
            elif impact >= 2.5 > likelihood:
                severity = 'high'
            elif impact < 2.5 <= likelihood:
                severity = 'medium'
            elif impact < 2.5 and likelihood < 2.5:
                severity = 'low'
        else:
            print("missing severity")

        #print("{}:{}:{}".format(vuln.InstanceInfo.InstanceID, vuln.InstanceInfo.InstanceSeverity, severity))
        return severity

    def concat_vuln_name(self, vuln):
        return "{} {} {}:{}".format(vuln.ClassInfo.Type, vuln.ClassInfo.Subtype,
                                    self.vulns[vuln.InstanceInfo.InstanceID]['filename'],
                                    self.vulns[vuln.InstanceInfo.InstanceID]['line'] )

    def _prepare_description_templates(self):

        for description in self.fvdl.Description:

            self.descriptions[description.get("classID")] = {}

            if description.get('classID') not in self.vuln_classes:
                continue

            tips = ""
            if hasattr(description, 'Tips'):
                for tip in description.Tips.getchildren():
                    tips += "\n" + tip.text

            htmlparser = HTMLParser()
            self.descriptions[description.get("classID")]['text'] = htmlparser.unescape(
            "Summary:\n{}\n\nExplanation:\n{}\n\nRecommendations:\n{}\n\nTips:{}".format(
                description.Abstract, description.Explanation, description.Recommendations, tips))

            #group vuln references
            references = []
            for reference in description.References.getchildren():

                for attr in dir(reference):
                    if attr == '__class__':
                        break

                    references.append("{}:{}\n".format(attr, getattr(reference, attr)))

            self.descriptions[description.get("classID")]['references'] = references

    def format_description(self, vulnID):
               
        text = self.descriptions[self.vulns[vulnID]['class']]['text']
        replacements = self.vulns[vulnID]['replacements']
        if not replacements:
            return text

        #special chars that must shown as-is, have the hmtlentity value duplicated    
        text = self.remove_extra_chars.sub(r"&\1;", text)
        previous_key = None
        #attempt to make replacements generic, not working yet
        for placeholder in self.replacements_holders.findall(text, re.MULTILINE):

            match = self.replacements_idx2.search(placeholder)

            replace_with = ""
            if match:
                idx = match.group(1)
                previous_key = idx
                if match.group(3):
                    idx = match.group(3)

                # idx = self.replacements_idx.search(placeholder).group(1)
                # if replacements:
                try:
                    replace_with = replacements[idx]
                except KeyError as e:
                    replace_with = ''
                    # if idx == 'SourceFunction':
                    #     replace_with = 'function'
                    # else:
                    #     #import pdb; pdb.set_trace()
                    #     replace_with = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            text = text.replace(placeholder, replace_with)

        text += '{}\n Instance ID: {} \n'.format(text, vulnID)
        return text


    def search_for_keyreplacements(self, key, skip_supressed=False):
        
        for vuln in self.fvdl.Vulnerabilities.iterchildren():
            vulnid = vuln.InstanceInfo.InstanceID
            _supressed = False
            _haskey = False
            if vulnid in self.suppressed:
                if skip_supressed:
                    continue
                _supressed = True

            repls = []
            try:
                for repl in vuln.AnalysisInfo.Unified.ReplacementDefinitions.iterchildren(
                    tag="{xmlns://www.fortifysoftware.com/schema/fvdl}Def"):
                    #print("{}:{}".format(repl.get('key'),repl.get("value")))                  
                    repls.append(repl.get('value'))
                    _last_entry = None
                    for _last_entry in vuln.AnalysisInfo.Unified.Trace.Primary.iterchildren():
                        pass
                    path = _last_entry.Node.SourceLocation.get('path')
                    if repl.get('key') == key:
                        _haskey = True
            except AttributeError:
                _haskey = False

            yield (vulnid, vuln.ClassInfo.ClassID.text, repls, path)
            #yield (vulnid, _haskey, _supressed, vuln.ClassInfo.ClassID)   


def createPlugin():
    return FortifyPlugin()

if __name__ == '__main__':
    
    with open('/home/mariano/xtras/fortify/jeopardySAST.fpr', 'r') as f:
        fp = FortifyParser(f.read())
        for vuln in fp.search_for_keyreplacements('SourceFunction', skip_supressed=True):
            pass
            #print(vuln)

        for vulnID in fp.vulns.keys():
            pass
            # print("{}{}{}".format("="*50, vulnID, "="*50))
            # print(fp.vulns[vulnID]['replacements'])
            # print("{}{}{}".format("="*50, vulnID, "="*50))
            fp.format_description(vulnID)
            # print("{}|{}|{}").format(vulnID, fp.vulns[vulnID].get('name'), fp.vulns[vulnID].get('severity'))