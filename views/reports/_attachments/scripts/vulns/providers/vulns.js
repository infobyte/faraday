// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager', 
        ['Vuln', 'WebVuln', 'BASEURL', '$filter', '$http', '$q', 'attachmentsFact', 'hostsManager', 'servicesManager', 
        function(Vuln, WebVuln, BASEURL, $filter, $http, $q, attachmentsFact, hostsManager, servicesManager) {
        var vulnsManager = {};
        
        vulnsManager.vulns = [];
        vulnsManager.vulns_indexes = {};

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

        vulnsManager._loadServices = function(services) {
            var res = {};

            services.forEach(function(service) {
                res[service._id] = "(" + service['ports'].join(",") + "/" + service['protocol'] + ") " + service['name'];
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
                        self.vulns_indexes[vuln._id] = self.vulns.length;
                        self.vulns.push(vuln);
                        var parents = [hostsManager.getHosts(ws), hostsManager.getAllInterfaces(ws), servicesManager.getServices(ws)];

                        $q.all(parents)
                            .then(function(ps) {
                                var hosts = self._loadHosts(ps[0], ps[1]);
                                var services = self._loadServices(ps[2]);

                                self.vulns.forEach(function(vuln) {
                                    var pid = vuln.parent.split(".")[0];
                                    if (hosts.hasOwnProperty(pid)) {
                                        vuln.target = hosts[pid]["target"];
                                        vuln.hostnames = hosts[pid]["hostnames"];
                                    }
                                    if(services.hasOwnProperty(vuln.parent)) vuln.service = services[vuln.parent];
                                });
                            });

                        deferred.resolve(self.resp);
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
            var deferred = $q.defer(),
            self = this;
            vuln.remove().then(function(){
                var index = self.vulns_indexes[vuln._id];
                for (var i = index + 1; i < self.vulns.length; i++) {
                    self.vulns_indexes[self.vulns[i]._id] = self.vulns_indexes[self.vulns[i]._id] - 1;
                }
                self.vulns.splice(self.vulns_indexes[vuln._id], 1);
                delete self.vulns_indexes[vuln._id];
                deferred.resolve();
            }, function(err){
                deferred.reject(err);
            });

            return deferred.promise
        };

        vulnsManager.getVulns = function(ws) {
            var deferred = $q.defer(),
            self = this;

            $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                .success(function(data) {
                    self.vulns.splice(0, self.vulns.length);
                    self.vulns_indexes = {};
                    for(var i = 0; i < data.rows.length; i++) {
                        var vulnData = data.rows[i].value;
                        try {
                            if(vulnData.type == "Vulnerability") {
                                var vuln = new Vuln(ws, vulnData);
                            } else {
                                var vuln = new WebVuln(ws, vulnData);
                            }
                            self.vulns_indexes[vuln._id] = self.vulns.length;
                            self.vulns.push(vuln);
                        } catch(e) {
                            console.log(e.stack);
                        }
                    }

                    var parents = [hostsManager.getHosts(ws), hostsManager.getAllInterfaces(ws), servicesManager.getServices(ws)];

                    $q.all(parents)
                        .then(function(ps) {
                            var hosts = self._loadHosts(ps[0], ps[1]);
                            var services = self._loadServices(ps[2]);

                            self.vulns.forEach(function(vuln) {
                                var pid = vuln.parent.split(".")[0];

                                if(hosts.hasOwnProperty(pid)) {
                                    vuln.target = hosts[pid]["target"];
                                    vuln.hostnames = hosts[pid]["hostnames"];
                                }
                                if(services.hasOwnProperty(vuln.parent)) vuln.service = services[vuln.parent];
                            });
                            deferred.resolve(self.vulns);
                        });
                })
                .error(function() {
                    deferred.reject("Unable to retrieve vulnerabilities from Couch");
                });

            return deferred.promise;
        };

        vulnsManager.getConfirmedVulns = function(ws) {
            var deferred = $q.defer(),
            self = this;

            $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                .success(function(data) {
                    self.vulns.splice(0, self.vulns.length);
                    self.vulns_indexes = {};
                    for(var i = 0; i < data.rows.length; i++) {
                        var vulnData = data.rows[i].value;
                        if(vulnData.confirmed === true) {
                            try {
                                if(vulnData.type == "Vulnerability") {
                                    var vuln = new Vuln(ws, vulnData);
                                } else {
                                    var vuln = new WebVuln(ws, vulnData);
                                }
                                self.vulns_indexes[vuln._id] = self.vulns.length;
                                self.vulns.push(vuln);
                            } catch(e) {
                                console.log(e.stack);
                            }
                        }
                    }

                    var parents = [hostsManager.getHosts(ws), hostsManager.getAllInterfaces(ws)];

                    $q.all(parents)
                        .then(function(ps) {
                            var hosts = self._loadHosts(ps[0], ps[1]);

                            self.vulns.forEach(function(vuln) {
                                var pid = vuln.parent.split(".")[0];
                                if (hosts.hasOwnProperty(pid)) {
                                    vuln.target = hosts[pid]["target"];
                                    vuln.hostnames = hosts[pid]["hostnames"];
                                }
                            });
                        });

                    deferred.resolve(self.vulns);
                })
                .error(function() {
                    deferred.reject("Unable to retrieve vulnerabilities from Couch");
                });

            return deferred.promise;
        };

        vulnsManager.updateVuln = function(vuln, data) {
            var deferred = $q.defer(),
            self = this;
            vuln.update(data).then(function(){
                self.vulns[self.vulns_indexes[vuln._id]] = vuln;
                deferred.resolve(vuln);
            }, function(err){
                deferred.reject(err);
            });
            return deferred.promise;
        };

        return vulnsManager;
    }]);
