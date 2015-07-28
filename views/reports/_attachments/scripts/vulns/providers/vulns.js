// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager', 
        ['Vuln', 'WebVuln', 'BASEURL', '$filter', '$http', '$q', 'attachmentsFact', 
        function(Vuln, WebVuln, BASEURL, $filter, $http, $q, attachmentsFact) {
        var vulnsManager = {};

        vulnsManager.vulns = [];
        vulnsManager.update_seq = 0;

        // receives data from Couch, loads vulns property
        vulnsManager._load = function(ws, data) {
            var self = this,
            vulns = [];

            for(var i = 0; i < data.length; i++) {
                var vulnData = data[i].value;
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

            self.vulns = vulns;

            return self.vulns;
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

                vuln.save().then(function() {
                    self.getVulns(ws).then(function() {
                        deferred.resolve();
                    }, function() {
                        deferred.reject();
                    });
                }, function() {
                    deferred.reject();
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
                .then(function() {
                    deferred.resolve(self.vulns);
                })
                .catch(function (err) {
                deferred.reject(err);
                });

            return deferred.promise;
        };

        vulnsManager.getVulns = function(ws) {
            var deferred = $q.defer(),
            self = this;

            $http.get(BASEURL + ws)
                .success(function(latest) {
                    if(latest.update_seq > self.update_seq) {
                        self.update_seq = latest.update_seq;
                        $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                            .success(function(data) {
                                deferred.resolve(self._load(ws, data.rows));
                            })
                            .error(function() {
                                deferred.reject();
                            });
                    }
                })
                .error(function() {
                    deferred.reject();
                });

            return deferred.promise;
        };

        vulnsManager.updateVuln = function(ws, vuln, data) {
            var deferred = $q.defer(),
            self = this;

            vuln.update(data).then(function(resp) {
                self.getVulns(ws).then(function(vulns) {
                    deferred.resolve(vulns);
                }, function() {
                    deferred.reject();
                });
            }, function() {
                deferred.reject();
            });

            return deferred.promise;
        };

        return vulnsManager;
    }]);
