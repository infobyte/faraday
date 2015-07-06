// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('statusReportFact', ['vulnsFact', 'vulnsWebFact', 'vulnsManager', 'hostsManager', 'workspacesFact', function(vulnsFact, vulnsWebFact, vulnsManager, hostsManager, workspacesFact) {
        var statusReportFact = {};

/*
        statusReportFact.getVulns = function(ws) {
            var vulns       = vulnsFact.get(ws);
            var vulnsWeb    = vulnsWebFact.get(ws);
            var hosts       = hostsManager.get(ws);
            vulns.forEach(function(element, index, array) {
                if (element.parent in hosts) {
                    element.target = hosts[element.parent].name;
                }
            });
            vulnsWeb.forEach(function(element, index, array) {
                if (element.parent in hosts) {
                    element.target = hosts[element.parent].name;
                }
            });
            return vulnsWeb.concat(vulns);
        };
*/

        statusReportFact.putVulns = function(ws, vuln, callback) {
            if(vuln.web) {
                vulnsWebFact.put(ws, vuln, callback);
            } else {
                vulnsFact.put(ws, vuln, callback);
            }
        };

        statusReportFact.removeVulns = function(ws, vuln) {
            vulnsFact.remove(ws, vuln);
        };

        statusReportFact.getWorkspaces = function() {
            return workspacesFact.list();
        };

        return statusReportFact;
    }]);
