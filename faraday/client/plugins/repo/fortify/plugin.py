import base64
import io
import re
from HTMLParser import HTMLParser
from zipfile import ZipFile

import html2text
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

    def _process_fvdl_vulns(self, fp):

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

    def _process_webinspect_vulns(self, fp):
        for vuln_data in fp.sast_vulns:
            host_id = self.createAndAddHost(
                vuln_data['host'] or vuln_data['website'])

            service_name = vuln_data['service'].get('name', 'unknown')
            protocol_name = 'line number'
            if vuln_data['service']['port'] == '443':
                service_name = 'https'
                protocol_name = 'tcp'
            if vuln_data['service']['port'] == '80':
                service_name = 'http'
                protocol_name = 'tcp'

            service_id = self.createAndAddServiceToHost(
                host_id,
                service_name,
                protocol=protocol_name,
                ports=[vuln_data['service']['port']])

            self.createAndAddVulnWebToService(
                host_id, service_id,
                vuln_data['name'],
                website=vuln_data['website'] or '',
                path=vuln_data['path'] or '',
                query=vuln_data['query'] or '',
                method=vuln_data['method'] or '',
                request=vuln_data['request'] or '',
                ref=vuln_data['references'],
                response=vuln_data['response'] or '',
                desc=vuln_data['description'],
                #resolution=vuln_data[''],
                severity=vuln_data['severity']
            )

    def parseOutputString(self, output, debug=False):
        fp = FortifyParser(output)
        if fp.fvdl is not None:
            self._process_fvdl_vulns(fp)
        if fp.webinspect is not None:
            self._process_webinspect_vulns(fp)

        return True


class FortifyParser:
    """  
    Parser for fortify on demand
    """

    def __init__(self, output):
        self.vulns = {}
        self.sast_vulns = []
        self.hosts = {}
        self.fvdl = None
        self.webinspect = None
        self.audit = None
        self.suppressed = []
        self.vuln_classes = []
        self.descriptions = {}

        self._uncompress_fpr(output)
        self._extract_vulns()
        self._prepare_description_templates()

        # regexes used in format_description
        self.remove_extra_chars = re.compile(r'&amp;(\w*);')
        self.replacements_idx = re.compile(r'<Replace key="(.*?)"[\s\/].*?>')
        self.replacements_holders = re.compile(r'<Replace key=".*?"[\s\/].*?>')
        self.replacements_idx2 = re.compile(r'<Replace key="(.*?)"(\slink="(.*?)")?[\s\/].*?>')

    def _uncompress_fpr(self, output):
        with ZipFile(io.BytesIO(output)) as fprcontent:
            try:
                self.fvdl = objectify.fromstring(fprcontent.read('audit.fvdl'))
            except KeyError:
                pass
            try:
                self.webinspect = objectify.fromstring(fprcontent.read('webinspect.xml'))
            except KeyError:
                pass
            try:
                self.audit = objectify.fromstring(fprcontent.read('audit.xml'))
            except KeyError:
                pass

    def _process_fvdl(self):
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

            # placeholder for storing hosts ids when created in main plugin method
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

    def _process_webinspect(self):
        for session in self.webinspect.getchildren():
            hostname = session.Host.text
            port = session.Port.text
            service_data = {}
            if port:
                service_data['port'] = port

            path = session.Request.Path.text
            query = session.Request.FullQuery.text
            method = session.Request.Method.text
            request = ''
            if session.RawRequest.text:
                request = base64.b64decode(session.RawRequest.text)
            response = ''
            if session.RawResponse.text:
                response = base64.b64decode(session.RawResponse.text)
            status_code = session.Response.StatusCode.text

            for issues in session.Issues:
                for issue_data in issues.getchildren():
                    params = ''
                    check_type = issue_data.CheckTypeID
                    if check_type.text.lower() != 'vulnerability':
                        # TODO: when plugins accept tags, we shoudl this as a tag.
                        pass
                    name = issue_data.Name.text
                    external_id = issue_data.VulnerabilityID.text
                    faraday_severities = {
                        0: 'info',
                        1: 'low',
                        2: 'med',
                        3: 'high',
                        4: 'critical'
                    }
                    severity = faraday_severities[issue_data.Severity]
                    references = []
                    try:
                        classifications = issue_data.Classifications.getchildren()
                    except AttributeError:
                        classifications = []

                    for classification in classifications:
                        references.append(classification.text)

                    # Build description
                    description = u''
                    for report_section in issue_data.findall('./ReportSection'):
                        description += u'{} \n'.format(report_section.Name.text)
                        description += u'{} \n'.format(report_section.SectionText.text)
                    description += u'{} \n'.format(issue_data.get('id'))

                    h = html2text.HTML2Text()
                    description = h.handle(description)

                    for repro_step in issue_data.findall('./ReproSteps'):
                        step = repro_step.ReproStep
                        if step is not None:
                            try:
                                params = step.PostParams.text
                            except AttributeError:
                                pass

                    if not hostname:
                        # This seems to be a mobile app
                        hostname = session.URL.text

                    if not port:
                        service_data['name'] = step.Url.text
                        service_data['port'] = step.sourceline

                    self.sast_vulns.append({
                        "host": hostname,
                        "severity": severity,
                        "service": service_data,
                        "name": name,
                        "description": description,
                        "external_id": external_id,
                        "references": references,
                        "method": method,
                        "query": query,
                        "response": response,
                        "request": request,
                        "path": path,
                        "params": params,
                        "status_code": status_code,
                        "website": session.URL.text
                    })

    def _extract_vulns(self):
        # make list of false positives
        try:
            issue_list = self.audit.IssueList.iterchildren()
        except AttributeError:
            issue_list = []

        for issue in issue_list:
            if issue.get('suppressed', 'false').lower() == 'true':
                self.suppressed.append(issue.get('instanceId'))

        if self.fvdl:
            self._process_fvdl()

        if self.webinspect is not None:
            self._process_webinspect()

    def calculate_severity(self, vuln):

        severity = None  # ["critical", "high", "medium", "low", "informational", "unclassified"]
        rulepath = objectify.ObjectPath("FVDL.EngineData.RuleInfo.Rule")
        impact = None
        probability = None
        accuracy = None

        # XML path /FVDL/EngineData/RuleInfo/Rule (many)/MetaInfo/Group (many) the attribute "name"
        # are keys for vuln properties

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

        # print("{}:{}:{}".format(vuln.InstanceInfo.InstanceID, vuln.InstanceInfo.InstanceSeverity, severity))
        return severity

    def concat_vuln_name(self, vuln):
        return "{} {} {}:{}".format(vuln.ClassInfo.Type, vuln.ClassInfo.Subtype,
                                    self.vulns[vuln.InstanceInfo.InstanceID]['filename'],
                                    self.vulns[vuln.InstanceInfo.InstanceID]['line'])

    def _prepare_description_templates(self):
        if not self.fvdl:
            return
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

            # group vuln references
            references = []
            try:
                children = description.References.getchildren()
            except AttributeError:
                children = []

            for reference in children:

                for attr in dir(reference):
                    if attr == '__class__':
                        break

                    references.append("{}: {}\n".format(attr, getattr(reference, attr)))

            self.descriptions[description.get("classID")]['references'] = references

    def format_description(self, vulnID):

        text = self.descriptions[self.vulns[vulnID]['class']]['text']
        replacements = self.vulns[vulnID]['replacements']
        if not replacements:
            return text

        # special chars that must shown as-is, have the hmtlentity value duplicated
        text = self.remove_extra_chars.sub(r"&\1;", text)

        for placeholder in self.replacements_holders.findall(text, re.MULTILINE):

            torepl = '<Replace key="{}"/>'
            match = self.replacements_idx2.search(placeholder)

            replace_with = ""
            if match:
                idx = match.group(1)
                if match.group(3):
                    idx = match.group(3)
                    _filekey = "{}.file".format(idx)
                    _linekey = "{}.line".format(idx)
                    text = text.replace(placeholder, "").replace(
                        torepl.format(_filekey), replacements[_filekey]).replace(
                        torepl.format(_linekey), replacements[_linekey])
                    continue

                try:
                    replace_with = replacements[idx]
                except KeyError:
                    # Nothing to replace, use empty string
                    text = text.replace(placeholder, "")

            text = text.replace(placeholder, replace_with)

        text += '{}\n Instance ID: {} \n'.format(text, vulnID)
        h = html2text.HTML2Text()
        description = h.handle(text)
        return text


def createPlugin():
    return FortifyPlugin()


if __name__ == '__main__':

    with open('/Users/lcubo/workspace/faraday/tests/data/fortify/webgoatnetSAST.fpr', 'r') as f:
        fp = FortifyParser(f.read())
        for vulnID in fp.vulns.keys():
            print("{}{}{}".format("="*50, vulnID, "="*50))
            print(fp.vulns[vulnID]['replacements'])
            print("{}{}{}".format("="*50, vulnID, "="*50))
            print(fp.format_description(vulnID))
            print("{}|{}|{}").format(vulnID, fp.vulns[vulnID].get('name'), fp.vulns[vulnID].get('severity'))
