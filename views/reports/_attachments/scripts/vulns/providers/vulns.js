// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager', 
        ['Vuln', 'WebVuln', 'BASEURL', '$filter', '$http', '$q', 'attachmentsFact', 
        function(Vuln, WebVuln, BASEURL, $filter, $http, $q, attachmentsFact) {
        var vulnsManager = {};

        // receives data from Couch, loads vulns property

        vulnsManager.createVuln = function(ws, data) {
            var deferred = $q.defer(),
            self = this;

            try {
                if(data.type == "Vulnerability") {
                    var vuln = new Vuln(ws, data);
                } else {
                    var vuln = new WebVuln(ws, data);
                }

                vuln.save()
                    .then(function() {
                        return self.getVulns(ws);
                    })
                    .catch(function(err) {
                        deferred.reject(err);
                    });
            } catch(e) {
                console.log(e.stack);
                deferred.reject(e.name + ": " + e.message);
            }

            return deferred.promise;
        };

        vulnsManager.deleteVuln = function(ws, vuln) {
            var self = this;
            var deferred = $q.defer();

            vuln.remove()
                .then(function() {
                    return self.getVulns(ws);
                })
                .catch(function(err) {
                    deferred.reject(err);
                });

            return deferred.promise;
        };

        vulnsManager.getVulns = function(ws) {
            var deferred = $q.defer(),
            self = this,
            vulns = [];

            $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                .success(function(data) {
                    for(var i = 0; i < data.rows.length; i++) {
                        var vulnData = data.rows[i].value;
                        try {
                            if(vulnData.type == "Vulnerability") {
                                var vuln = new Vuln(ws, vulnData);
                                vulns.push(vuln);
                            } else {
                                var vuln = new WebVuln(ws, vulnData);
                                vulns.push(vuln);
                            }
                        } catch(e) {
                            console.log(e.stack);
                        }
                    }
                    deferred.resolve(vulns);
                })
                .error(function() {
                    deferred.reject("Unable to retrieve vulnerabilities from Couch");
                });

            return deferred.promise;
        };

        vulnsManager.updateVuln = function(ws, vuln, data) {
            var deferred = $q.defer(),
            self = this;

            vuln.update(data)
                .then(function(resp) {
                    return self.getVulns(ws);
                })
                .catch(function(err) {
                    deferred.reject(err);
                });

            return deferred.promise;
        };

        return vulnsManager;
    }]);
