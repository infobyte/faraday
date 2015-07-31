// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager', 
        ['Vuln', 'WebVuln', 'BASEURL', '$filter', '$http', '$q', 'attachmentsFact', 'hostsManager', 
        function(Vuln, WebVuln, BASEURL, $filter, $http, $q, attachmentsFact, hostsManager) {
        var vulnsManager = {};

        vulnsManager._loadHosts = function(hosts, interfaces) {
            var res = {};

            interfaces.forEach(function(interf) {
                var host = interf.parent;
                if(!res.hasOwnProperty(host)) res[host] = {};
                if(!res[host].hasOwnProperty("hostnames")) res[host]["hostnames"] = [];
                res[host]["hostnames"] = res[host]["hostnames"].concat(interf.hostnames);
            });

            hosts.forEach(function(host) {
                if(!res.hasOwnProperty(host._id)) res[host._id] = {};
                res[host._id]["target"] = host.name;
            });

            return res;
        };

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
                    .then(function(resp) {
                        deferred.resolve(resp);
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

        vulnsManager.deleteVuln = function(vuln) {
            return vuln.remove();
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

                    var parents = [hostsManager.getHosts(ws), hostsManager.getAllInterfaces(ws)];

                    $q.all(parents)
                        .then(function(ps) {
                            var hosts = self._loadHosts(ps[0], ps[1]);

                            vulns.forEach(function(vuln) {
                                var pid = vuln.parent.split(".")[0];
                                vuln.target = hosts[pid]["target"];
                                vuln.hostnames = hosts[pid]["hostnames"];
                            });
                        });

                    deferred.resolve(vulns);
                })
                .error(function() {
                    deferred.reject("Unable to retrieve vulnerabilities from Couch");
                });

            return deferred.promise;
        };

        vulnsManager.updateVuln = function(vuln, data) {
            return vuln.update(data);
        };

        return vulnsManager;
    }]);
