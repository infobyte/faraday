// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('referenceService', function () {
        return {
            processReference: function (text) {
                var url = 'http://google.com/',
                    url_pattern = new RegExp('^(http|https):\\/\\/?');

                var cve_pattern = new RegExp(/^CVE-\d{4}-\d{4,7}$/),
                    cwe_pattern = new RegExp(/^CWE(-|:)\d{1,7}$/),
                    edb_pattern = new RegExp(/^EDB-ID:\s?\d{1,}$/),
                    osvdb_pattern = new RegExp(/^OSVDB:\s?\d{1,}$/);

                var cve = text.search(cve_pattern),
                    cwe = text.search(cwe_pattern),
                    edb = text.search(edb_pattern),
                    osvdb = text.search(osvdb_pattern);

                if (url_pattern.test(text)) {
                    url = text;
                } else if (cve > -1) {
                    url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + text.substring(cve + 4);
                } else if (cwe > -1) {
                    url = "https://cwe.mitre.org/data/definitions/" + text.substring(cwe + 4) + ".html";
                } else if (osvdb > -1) {
                    url = "http://osvdb.org/show/osvdb/" + text.substring(osvdb + 6);
                } else if (edb > -1) {
                    url = "https://www.exploit-db.com/exploits/" + text.substring(edb + 7);
                } else {
                    url += 'search?q=' + text;
                }

                return url;
            }
        }
    });