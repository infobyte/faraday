// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Vuln', ['BASEURL', '$q', 'ServerAPI', 'attachmentsFact', 
    function(BASEURL, $q, ServerAPI, attachmentsFact) {
        Vuln = function(ws, data) {
            var now = new Date(),
            date = now.getTime() / 1000.0;

            this._id = "";
            this._rev = "";
            this._attachments = {};
            this.confirmed = true;
            this.data = "";
            this.desc = "";
            this.easeofresolution = "";
            this.hostnames = "";
            this.impact = {
                accountability: false,
                availability: false,
                confidentiality: false,
                integrity: false
            };
            this.metadata = {
                update_time: date,
                update_user: "",
                update_action: 0,
                creator: "UI Web",
                create_time: date,
                update_controller_action: "UI Web New",
                owner: ""
            };
            this.name = "";
            this.obj_id = "";
            this.owner = "";
            this.owned = "";
            this.parent = "";
            this.refs = "";
            this.resolution = "";
            this.service = "";
            this.severity = "";
            this.target = "";
            this.type = "Vulnerability";
            this.ws = "";
            this.status = "opened";
            this.policyviolations = "";

            if(data) {
                if(data.name === undefined || data.name === "") {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(ws, data);
            }
        };

        var public_properties = [
            '_attachments', 'confirmed', 'data', 'desc', 'easeofresolution',
            'impact', 'name', 'owned', 'policyviolations', 'refs', 'resolution',
            'severity', 'status',
        ];

        var saved_properties = public_properties.concat(
            ['_id', '_rev', 'metadata', 'obj_id', 'owner', 'parent', 'type']);

        Vuln.prototype = {
            public_properties: public_properties,
            saved_properties: saved_properties,
            set: function(ws, data) {
                var self = this;

                // new vuln
                if(data._id === undefined) {
                    var id = CryptoJS.SHA1(data.name + "." + data.desc).toString();
                    self._id = data.parent + "." + id;
                    self.obj_id = id;
                } else {
                    self._id = data._id;
                    self.obj_id = data.obj_id;
                    if(data._rev !== undefined) self._rev = data._rev;
                    if(data.metadata !== undefined) self.metadata = data.metadata;
                    if(data.target !== undefined) self.target = data.target;
                    if(data.hostnames !== undefined) self.hostnames = data.hostnames;
                    if(data.service !== undefined) self.service = data.service;
                }

                if(data.owner !== undefined) self.owner = data.owner;
                self.ws = ws;
                if(data.parent !== undefined) self.parent = data.parent;

                self.public_properties.forEach(function(property) {
                    if(data[property] !== undefined) self[property] = data[property];
                });
            },
            remove: function() {
                var self = this;
                return ServerAPI.deleteVuln(self.ws, self._id, self._rev);

            },
            _update: function(vuln, data) {
                var deferred = $q.defer(),
                self = this,
                url = BASEURL + vuln.ws + "/" + vuln._id;

                var now = new Date(),
                date = now.getTime();

                vuln.metadata.update_time = date;

                vuln.public_properties.forEach(function(prop) {
                    if(data.hasOwnProperty(prop)) {
                        if(prop != "_attachments") vuln[prop] = data[prop];
                    }
                });

                if(data._attachments !== undefined) {
                    var files = {},
                    stubs = {};
                    vuln._attachments = {};

                    // the list of evidence may have mixed objects, some of them already in CouchDB, some of them new
                    // new attachments are of File type and need to be processed by attachmentsFact.loadAttachments 
                    // old attachments are of type Object and they represent a Stub, nothing should be done to them
                    for(var name in data._attachments) {
                        if(data._attachments.hasOwnProperty(name)) {
                            if(data._attachments[name] instanceof File) {
                                files[name] = data._attachments[name];
                            } else {
                                stubs[name] = data._attachments[name];
                            }
                        }
                    }
                    angular.extend(vuln._attachments, stubs);
                    attachmentsFact.loadAttachments(files).then(function(atts) {
                        angular.extend(vuln._attachments, atts);
                        self._save(vuln, true)
                            .then(function(response) {
                                self.set(self.ws, vuln);
                                self._rev = response.rev;
                                deferred.resolve();
                            }, function() {
                                deferred.reject();
                            });
                    });
                } else {
                    self._save(vuln, true)
                        .then(function(response) {
                            self.set(self.ws, vuln);
                            self._rev = response.rev;
                            deferred.resolve();
                        }, function() {
                            deferred.reject();
                        });
                }

                return deferred.promise;
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
                vuln.ws = self.ws;

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
                    self._save(resp, false)
                        .then(function(data) {
                            self._rev = data.rev;
                            deferred.resolve(self);
                        }, function(data, status, headers, config) {
                            deferred.reject(status);
                        });
                }, function() {
                    deferred.reject();
                });

                return deferred.promise;
            },
            _save: function(data, update) {
                var doc = {};
                if (typeof update === "undefined") {var update = false};
                for (var property in data) {
                    if (this.saved_properties.indexOf(property) != -1) {
                        doc[property] = data[property];
                    }
                }
                if (update) {
                    return ServerAPI.updateVuln(this.ws, data);
                }
                else {
                    return ServerAPI.createVuln(this.ws, data);
                }
        }
        }
        return Vuln;
    }]);
