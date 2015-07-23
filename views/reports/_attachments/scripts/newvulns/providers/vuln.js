// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Vuln', ['BASEURL', '$http', function(BASEURL, $http) {
        Vuln = function(ws, data){
            if(data) {
                if(data.name === undefined || data.name === "") {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(ws, data);
            }
        };

        Vuln.prototype = {
            set: function(ws, data) {
                var evidence = [],
                impact = {
                    accountability: false,
                    availability: false,
                    confidentiality: false,
                    integrity: false
                },
                metadata = {},
                now = new Date(),
                date = now.getTime();

                if(data.attachments !== undefined) {
                    for(var attachment in data.attachments) {
                        if(data.attachments.hasOwnProperty(attachment)) {
                            evidence.push(attachment);
                        }
                    }
                }

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

                    metadata.update_time = date;
                    if(data.metadata.update_user !== undefined) metadata.update_user = data.metadata.update_user;
                    if(data.metadata.update_action !== undefined) metadata.update_action = data.metadata.update_action;
                    if(data.metadata.creator !== undefined) metadata.creator = data.metadata.creator;
                    if(data.metadata.create_time !== undefined) metadata.create_time = data.metadata.create_time;
                    if(data.metadata.update_controller_action !== undefined) metadata.update_controller_action = data.metadata.update_controller_action;
                    if(data.metadata.owner !== undefined) metadata.owner = data.metadata.owner;
                }

                this.date = date;
                this.metadata = metadata;
                this.owner = "";
                this.type = "Vulnerability";
                this.ws = ws;

                // user-generated content
                this._attachments = evidence;
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
                url = BASEURL + self.ws + "/" + self._id;
                return $http.delete(url);
            },
            update: function(data) {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id,
                vuln = new Vuln(self.ws, self);
                vuln.set(self.ws, data);
                return $http.put(url, vuln)
                    .success(function(response) {
                        self.set(self.ws, data);
                        self._rev = response.rev;
                    });
            },
            save: function() {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id,
                vuln = {};
                angular.extend(vuln, self);
                // remove WEBUI-specific fields
                delete vuln._attachments;
                delete vuln.date;
                delete vuln.delete;
                delete vuln.web;
                delete vuln.ws;
                return $http.put(url, vuln)
                    .success(function(data) {
                        self._rev = data.rev;
                    });
            }
        }

        return Vuln;
    }]);
