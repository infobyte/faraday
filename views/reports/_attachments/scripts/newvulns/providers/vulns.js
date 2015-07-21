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
        vulnsManager._load = function(data) {
            var self = this,
            vulns = [];

            for(var i = 0; i < data.length; i++) {
                var vulnData = data[i].value;
                if(vulnData.type == "Vulnerability") {
                    var vuln = new Vuln(vulnData);
                } else {
                    var vuln = new WebVuln(vulnData);
                }
                vulns.push(vuln);
            }

            self.vulns = vulns;
        };

        vulnsManager.createVuln = function(ws, data) {
            var deferred = $q.defer(),
            self = this;

            if(data.type == "Vulnerability") {
                var vuln = new Vuln(data);
            } else {
                var vuln = new WebVuln(data);
            }

            vuln.save().then(function() {
                self.getVulns(ws);
                deferred.resolve();
            }, function() {
                deferred.reject();
            });

            return deferred.promise;
        };

        vulnsManager.deleteVuln = function(ws, vuln) {
            var self = this;

            return vuln.remove().then(function() {
                self.getVulns(ws);
            });
        };

        vulnsManager.getVulns = function(ws) {
            var self = this;
            return $http.get(BASEURL + ws)
                .then(function(latest) {
                    if(latest.data.update_seq > self.update_seq) {
                        self.update_seq = latest.data.update_seq;
                        $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                            .success(function(data) {
                                self._load(data.rows);
                            });
                    }
                });
        };

        vulnsManager.updateVuln = function(ws, vuln, data) {
            var self = this;

            return vuln.update(data).then(function(resp) {
                self.getVulns(ws);
            });
        };

/*
        //data comes from Couch
        //updates vuln or loads it
        vulnsManager._get = function(id, data) {
            var i = $filter('getByProperty')('_id', id, this.vulns),
            vuln = this.vulns[i];

            if(vuln) {
                vuln.set(data);
            } else if(data.type == "Vulnerability") {
                vuln = new Vuln(data);
                this.vulns.push(vuln);
            } else {
                vuln = new WebVuln(data);
                this.vulns.push(vuln);
            }

            return vuln;
        };

        vulnsManager._search = function(id) {
            var i = $filter('getByProperty')('_id', id, this.vulns);
            return this.vuln[i];
        };

        vulnsManager._latest = function(ws) {
            var deferred = $q.defer();
            $http.get(BASEURL + ws)
                .success(function(wsData) {
                    deferred.resolve(wsData.update_seq);
                })
                .error(function() {
                    deferred.reject("Error connecting to CouchDB");
                });

            return deferred.promise;
        };

        vulnsManager._load = function(id, ws) {
            var deferred = $q.defer(),
            self = this,
            url = BASEURL + ws + '/' + id;
            $http.get(url)
                .success(function(data) {
                    var vuln = self._get(data._id, data);
                    deferred.resolve(vuln);
                })
                .error(function() {
                    deferred.reject();
                });
            return deferred.promise;
        };

        vulnsManager._loadVulns = function(ws) {
            var deferred = $q.defer(),
            self = this;

            $http.get(BASEURL + ws + '/_design/vulns/_view/all')
                .success(function(vulnsArray) {
                    var vulns = [];
                    vulnsArray.rows.forEach(function(vulnData) {
                        vulnData.value._id = vulnData.id;
                        self._get(vulnData.value._id, vulnData.value);
                    });
                    deferred.resolve();
                })
                .error(function() {
                    deferred.reject();
                });

            return deferred.promise;
        };

        vulnsManager.getVulns = function(ws) {
            var deferred = $q.defer(),
            self = this;
            vulnsManager._latest(ws).then(function(latest) {
                if(latest > self.update_seq) {
                    self.update_seq = latest;
                    self._loadVulns(ws).then(function() {
                        deferred.resolve();
                    }, function() {
                        deferred.reject("Error loading vulnerabilities from CouchDB");
                    });
                } else {
                    deferred.resolve();
                }
            }, function() {
                deferred.reject("Error loading workspace data from CouchDB");
            });

            return deferred.promise;
        };

        vulnsManager.getVuln = function(ws, id, force_reload) {
            var deferred = $q.defer(),
            vuln = this._search(id);
            force_reload = force_reload || false;
            
            if(vuln && !force_reload) {
                deferred.resolve(vuln);
            } else {
                deferred.resolve(this._load(id, ws));
            } 

            return deferred.promise;
        };

        vulnsManager.createVuln = function(ws, vulnData) {
            var deferred = $q.defer(),
            self = this;

            if(vulnData.type === "Vulnerability") {
                var vuln = new Vuln(vulnData);
            } else if(vulnData.type === "VulnerabilityWeb") {
                var vuln = new WebVuln(vulnData);
            } else {
                deferred.reject("Error: Cannot create vulnerability using type '" + vulnData.type + "'");
            }

            if(vuln != undefined) {
                self.getVuln(ws, vuln._id).then(function() {
                    deferred.reject("Error: vuln already exists");
                }, function() {
                    // vuln doesn't exist, good to go
                    vuln.save(ws).then(function() {
                        vuln = self.getVuln(ws, vuln._id);
                        deferred.resolve(vuln);
                    }, function() {
                        deferred.reject("Error: vuln couldn't be saved");
                    });
                });
            }

            return deferred.promise;
        };

        vulnsManager.put = function(ws, vuln, callback) {
            var url = BASEURL + ws + "/" + vuln.id, 
            v = {
                "_rev":             vuln.rev,
            };
            if(typeof(vuln.evidence) != undefined && vuln.evidence != undefined) {
                // the list of evidence may have mixed objects, some of them already in CouchDB, some of them new
                // new attachments are of File type and need to be processed by attachmentsFact.loadAttachments 
                // old attachments are of type String (file name) and need to be processed by attachmentsFact.getStubs
                var stubs = [],
                files = [],
                names = [],
                promises = [];
                v._attachments = {};

                for(var name in vuln.evidence) {
                    if(vuln.evidence[name] instanceof File) {
                        files.push(vuln.evidence[name]);
                    } else {
                        stubs.push(name);
                    }
                }

                if(stubs.length > 0) promises.push(attachmentsFact.getStubs(ws, vuln.id, stubs));
                if(files.length > 0) promises.push(attachmentsFact.loadAttachments(files));

                $q.all(promises).then(function(result) {
                    result.forEach(function(atts) {
                        for(var name in atts) {
                            v._attachments[name] = atts[name];
                            names.push(name);
                        }
                    });
                    $http.put(url, v).success(function(d, s, h, c) {
                        callback(d.rev, names);
                    });
                });
            } else {
                $http.put(url, v).success(function(d, s, h, c) {
                    callback(d.rev, []);
                });
            }
        };

        vulnsManager.deleteVuln = function(ws, vuln) {
            return $http.delete(BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev)
                .success(function(resp) {
                    this.vulns = this.getVulns(ws);
                });
        };
*/

        return vulnsManager;
    }]);
