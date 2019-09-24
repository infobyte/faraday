import io
import re
from HTMLParser import HTMLParser
from zipfile import ZipFile
from lxml import objectify
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
                name=str(vuln),
                desc="", 
                ref=[],
                severity="", 
                resolution="", 
                data="", 
                external_id=None
            )
        return True


class FortifyParser():
    remove_extra_chars = re.compile(r'&amp;(\w*);')
    replacements_fmt = re.compile(r'<Replace key="(.*?)"[\s\/].*?>')

    def __init__(self, output):
        self.vulns = {}
        self.hosts = {}
        self.fvdl = None
        self.audit = None
        self.suppressed = []
        self.descriptions = {}

        self._uncompress_fpr(output)
        self._extract_vulns()
        self._prepare_description_templates()

    def _uncompress_fpr(self, output):
        with ZipFile(io.BytesIO(output)) as fprcontent:
            self.fvdl = objectify.fromstring(fprcontent.read('audit.fvdl'))
            self.audit = objectify.fromstring(fprcontent.read('audit.xml'))

    def _extract_vulns(self):
        for issue in self.audit.IssueList.iterchildren():
            if issue.get('suppressed') == 'true':
                self.suppressed.append(issue.get('instanceId'))

        for vuln in self.fvdl.Vulnerabilities.iterchildren():

            vulnID = vuln.InstanceInfo.InstanceID
            
            if vulnID in self.suppressed:
                continue

            self.vulns[vulnID] = {}   

            # the last children of Primary (Entry tags) always contains vuln filename and path
            _last_entry = None
            for _last_entry in vuln.AnalysisInfo.Unified.Trace.Primary.iterchildren():
                pass

            filename = _last_entry.Node.SourceLocation.get('path')

            self.vulns[vulnID]['host'] = filename
            self.vulns[vulnID]['rule'] = vuln.ClassInfo.ClassID
            self.vulns[vulnID]['replacements'] = {}
            
            #placeholder for storing hosts ids when created in main plugin method                    
            if filename not in self.hosts.keys():
                self.hosts[filename] = None
        
            # fortify bug that has no replacements, it shows blank in fortify dashboard
            if not hasattr(vuln.AnalysisInfo.Unified, "ReplacementDefinitions"):
                self.vulns[vulnID]['replacements'] = None 
                continue


            for repl in vuln.AnalysisInfo.Unified.ReplacementDefinitions.Def.iterchildren():
                self.vulns[vulnID]['replacements'][repl.get('key')] = repl.get('value')            

    def _prepare_description_templates(self):
        for description in self.fvdl.Description:

            tips = ""
            if hasattr(description, 'Tips'):
                for tip in description.Tips.getchildren():
                    tips += "\n" + tip.text

            #group vuln references
            references = ""
            for reference in description.References.getchildren():

                for attr in dir(reference):
                    if attr == '__class__':
                        break

                    references += "{}:{}\n".format(attr, getattr(reference, attr))

                references += "\n"

            htmlparser = HTMLParser()
            self.descriptions[description.get("classID")] = htmlparser.unescape(
            "Summary:\n{}\n\nExplanation:\n{}\n\nRecommendations:\n{}\n\nTips:{}\n\nReferences:\n{}".format(
                description.Abstract, description.Explanation, description.Recommendations, tips, references))

    def _format_description(self, vulnID):
               
        text = self.descriptions[self.vulns[vulnID]['rule']]
        replacements = self.vulns[vulnID]['replacements']
        
        #special chars that must shown as-is, have the hmtlentity value duplicated    
        text = self.remove_extra_chars.sub(r"&\1;", text)


        #attemp to make replacements generic, not working yet
        for match in self.replacements_fmt.finditer(text):
            replace_with = ""
            if replacements:
                replace_with = replacements[match.group(1)]

            self.replacements_fmt.sub(match.group(0), replace_with)
            text.replace('<Replace key="{}"/>'.format(match.group(1)), replace_with )


        #import pdb;pdb.set_trace();
        #text = text.replace('<Replace key="PrimaryCall.name"/>', repl['PrimaryCall.name'])
        #text = text.replace('<Replace key="SourceLocation.file"/>', repl['PrimaryCall.name'])
        #text = text.replace('<Replace key="SourceLocation.line"/>', repl['PrimaryCall.name'])
        #text = text.replace('<Replace key="SinkFunction" link="SinkLocation"/>', repl['PrimaryCall.name'])
        #text = text.replace('<Replace key="SinkLocation.file"/>', repl['PrimaryCall.name'])

        #print(text)
        return text


def createPlugin():
    return FortifyPlugin()


if __name__ == '__main__':
    
    with open('/home/mariano/xtras/fortify/jeopardySAST.fpr', 'r') as f:
        fp = FortifyParser(f.read())
        for vulnID in fp.vulns.keys():
            fp._format_description(vulnID)

        print(fp.descriptions)
