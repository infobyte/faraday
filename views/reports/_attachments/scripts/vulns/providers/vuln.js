// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Vuln', ['BASEURL', '$http', '$q', 'attachmentsFact', function(BASEURL, $http, $q, attachmentsFact) {
        Vuln = function(ws, data){
            if(data) {
                if(data.name === undefined || data.name === "") {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(ws, data);
            }
        };

        Vuln.prototype = {
            public_properties: [
                'name', 'desc', '_attachments', 'data', 'easeofresolution', 
                'impact', 'owned', 'refs', 'resolution', 'severity'
            ],
            set: function(ws, data) {
                var impact = {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                metadata = {},
                now = new Date(),
                date = now.getTime();

                // new vuln
                if(data._id === undefined) {
                    var id = CryptoJS.SHA1(data.name + "." + data.desc).toString();

                    this._id = data.parent + "." + id;
                    this.obj_id = id;

                    metadata.update_time = date;
                    metadata.update_user = "";
                    metadata.update_action = 0;
                    metadata.creator = "UI Web";
                    metadata.create_time = date;
                    metadata.update_controller_action = "UI Web New";
                    metadata.owner = "";
                } else {
                    this._id = data._id;
                    this.obj_id = data._id;
                    if(data._rev !== undefined) this._rev = data._rev;

                    if(this.metadata !== undefined) metadata = this.metadata; 
                }

                this.date = date;
                this.metadata = metadata;
                this.owner = "";
                this.type = "Vulnerability";
                this.ws = ws;

                // user-generated content
                if(data._attachments !== undefined) {
                    this._attachments = [];
                    for(var att in data._attachments) {
                        if(data._attachments.hasOwnProperty(att)) {
                            this._attachments.push(data._attachments[att]);
                        }
                    }
                }
                if(data.data !== undefined) this.data = data.data;
                if(data.desc !== undefined) this.desc = data.desc;
                if(data.easeofresolution !== undefined) this.easeofresolution = data.easeofresolution;
                if(data.impact !== undefined) {
                    this.impact = data.impact;
                    for(var prop in data.impact) {
                        if(data.impact.hasOwnProperty(prop)) {
                            this.impact[prop] = data.impact[prop];
                        }
                    }
                }
                if(data.name !== undefined && data.name !== "") this.name = data.name;
                if(data.owned !== undefined) this.owned = data.owned;
                if(data.parent !== undefined) this.parent = data.parent;
                if(data.refs !== undefined) this.refs = data.refs;
                if(data.resolution !== undefined) this.resolution = data.resolution;
                if(data.severity !== undefined) this.severity = data.severity;
            },
            remove: function() {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id + "?rev=" + self._rev;
                return $http.delete(url);
            },
            _update: function(vuln, data) {
                var self = this,
                url = BASEURL + vuln.ws + "/" + vuln._id;
                 
                vuln.public_properties.forEach(function(prop) {
                    if(vuln.hasOwnProperty(prop) && data.hasOwnProperty(prop)) {
                        vuln[prop] = data[prop];
                    }
                });

                return $http.put(url, vuln)
                    .success(function(response) {
                        self.set(self.ws, vuln);
                        self._rev = response.rev;
                    });
            },
            update: function(data) {
                var self = this,
                vuln = new Vuln(self.ws, self);
                return self._update(vuln, data);
            },
            populate: function() {
                var deferred = $q.defer(),
                self = this,
                vuln = {};

                vuln._id = self._id;
                vuln.metadata = self.metadata;
                vuln.obj_id = self.obj_id;
                vuln.owner = self.owner;
                vuln.parent = self.parent;
                vuln.type = self.type;

                self.public_properties.forEach(function(prop) {
                    if(prop !== "_attachments") vuln[prop] = self[prop];
                });

                if(self._attachments !== undefined) {
                    attachmentsFact.loadAttachments(self._attachments).then(function(atts) {
                        vuln._attachments = atts;
                        deferred.resolve(vuln);
                    }, function() {
                        deferred.reject("Unable to load attachments");
                    });
                } else {
                    deferred.resolve(vuln);
                }

                return deferred.promise;
            },
            save: function() {
                var deferred = $q.defer(),
                loadAtt,
                self = this,
                url = BASEURL + self.ws + "/" + self._id;
                
                self.populate().then(function(resp) {
                    $http.put(url, resp)
                        .success(function(data) {
                            self._rev = data.rev;
                            deferred.resolve(self);
                        }, function() {
                            deferred.reject();
                        });
                }, function() {
                });

/*
                if(self._attachments !== undefined) {
                    loadAtt = _loadAttachments(self._attachments);
                }

                $q.when(loadAtt).then(function(atts) {
                    vuln._attachments = atts;
                    
                    $http.put(url, vuln)
                        .success(function(data) {
                            self._rev = data.rev;
                            self._attachments = Object.keys(vuln._attachments);
                            deferred.resolve();
                        }, function() {
                            deferred.reject();
                        });
                }, function() {
                    $http.put(url, vuln)
                        .success(function(data) {
                            self._rev = data.rev;
                            deferred.resolve();
                        }, function() {
                            deferred.reject();
                        });
                });
*/

                return deferred.promise;
            }
        };

        _loadAttachments = function(evidence) {
            // the list of evidence may have mixed objects, some of them already in CouchDB, some of them new
            // new attachments are of File type and need to be processed by attachmentsFact.loadAttachments 
            // old attachments are of type String (file name) and need to be processed by attachmentsFact.getStubs
            var attachments = {},
            deferred = $q.defer(),
            files = [],
            promises = [],
            stubs = [];

            for(var name in evidence) {
                if(evidence[name] instanceof File) {
                    files.push(evidence[name]);
                } else {
                    stubs.push(name);
                }
            }

            if(stubs.length > 0) promises.push(attachmentsFact.getStubs(ws, vuln.id, stubs));
            if(files.length > 0) promises.push(attachmentsFact.loadAttachments(files));

            $q.all(promises).then(function(result) {
                result.forEach(function(atts) {
                    for(var name in atts) {
                        attachments[name] = atts[name];
                    }
                });
                deferred.resolve(attachments);
            }, function() {
                deferred.reject("Unable to load attachments");
            });

            return deferred.promise;
        };

        return Vuln;
    }]);
