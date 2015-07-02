// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager', ['BASEURL', '$http', '$q', 'attachmentsFact', function(BASEURL, $http, $q, attachmentsFact) {
        var vulnsManager = {};

        vulnsManager._objects = {};
        vulnsManager._get = function(id, data) {
            var vuln = this._objects[id];

            if(vuln) {
                vuln.set(data);
            } else if(data.type == "Vulnerability") {
                vuln = new Vuln(data);
                this._objects[id] = vuln;
            } else {
                vuln = new WebVuln(data);
                this._objects[id] = vuln;
            }

            return vuln;
        };

        vulnsManager._search = function(id) {
            return this._objects[id];
        };

        vulnsManager._load = function(id, ws, deferred) {
            var self = this;
            $http.get(BASEURL + '/' + ws + '/' + id)
                .success(function(data) {
                    var vuln = self._get(data._id, data);
                    deferred.resolve(vuln);
                })
                .error(function() {
                    deferred.reject();
                });
        };

        vulnsManager.get = function(ws) {
            var vulns = [],
            deferred = $q.defer(),
            url = BASEURL + ws +"/_design/vulns/_view/all";
            $http.get(url)
                .success(function(data, status, headers, config) {
                    deferred.resolve(data);
                })
                .error(function() {
                    deferred.reject();
                });
            return deferred.promise;

            $.getJSON(vulns_url, function(data) {
                $.each(data.rows, function(n, obj){
                    var evidence = [],
                    date = obj.value.date * 1000;
                    if(typeof(obj.value.attachments) != undefined && obj.value.attachments != undefined) {
                        for(var attachment in obj.value.attachments) {
                            evidence.push(attachment);
                        }
                    }
                    var v = {
                        "id":               obj.id,
                        "rev":              obj.value.rev,
                        "attachments":      evidence,
                        "couch_parent":     obj.value.parent,
                        "data":             obj.value.data,
                        "date":             date, 
                        "delete":           false,
                        "desc":             obj.value.desc,
                        "easeofresolution": obj.value.easeofresolution,
                        "impact":           obj.value.impact,
                        "meta":             obj.value.meta,
                        "name":             obj.value.name, 
                        "oid":              obj.value.oid,
                        "owned":            obj.value.owned,
                        "owner":            obj.value.owner,
                        "parent":           obj.key.substring(0, obj.key.indexOf('.')),
                        "refs":             obj.value.refs,
                        "resolution":       obj.value.resolution,
                        "selected":         false,
                        "severity":         obj.value.severity,
                        "type":             obj.value.type, 
                        "web":              false
                    };
                    vulns.push(v);
                });
            });
            return vulns;
        }

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
