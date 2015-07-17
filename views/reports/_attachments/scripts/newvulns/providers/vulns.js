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
                        var vuln = self._get(vulnData.value._id, vulnData.value);
                        vulns.push(vuln);
                    });
                    deferred.resolve(vulns);
                })
                .error(function() {
                    deferred.reject();
                });

            return deferred.promise;
        };

        vulnsManager.getVulns = function(ws) {
            var deferred = $q.defer();
            $http.get(BASEURL + ws)
                .success(function(wsData) {
                    if(wsData.update_seq > vulnsManager.update_seq) {
                        vulnsManager.update_seq = wsData.update_seq;
                        //deferred.resolve(vulnsManager._loadVulns(ws));
                        vulnsManager._loadVulns(ws).then(function(vulns) {
                            vulnsManager.vulns = vulns;
                            deferred.resolve(vulnsManager.vulns);
                        }, function() {
                            deferred.reject("Error loading vulnerabilities from CouchDB");
                        });
                    } else {
                        deferred.resolve(vulnsManager.vulns);
                    }
                })
                .error(function() {
                    deferred.reject("Error loading workspace data");
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
                "data":             vuln.data,
                "desc":             vuln.desc,
                "easeofresolution": vuln.easeofresolution,
                "impact":           vuln.impact,
                "metadata":         vuln.meta,
                "name":             vuln.name,
                "obj_id":           vuln.oid,
                "owned":            vuln.owned,
                "owner":            vuln.owner,
                "parent":           vuln.couch_parent, 
                "refs":             vuln.refs,
                "resolution":       vuln.resolution,
                "severity":         vuln.severity, 
                "type":             vuln.type
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

        vulnsManager.remove = function(ws, vuln) {
            var url = BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev;
            $http.delete(url).success(function(d, s, h, c) {});
        };

        return vulnsManager;
    }]);
