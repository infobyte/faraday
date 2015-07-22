// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Vuln', ['BASEURL', '$http', function(BASEURL, $http) {
        Vuln = function(data){
            if(data) {
                if(data.name === "" || data.name === undefined) {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(data);
            }
        };

        Vuln.prototype = {
            set: function(data) {
                var evidence = [],
                metadata = {},
                now = new Date(),
                date = now.getTime(),
                selected = false;

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
                    if(data.selected !== undefined) selected = data.selected;

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
                this.selected = selected;
                this.type = "Vulnerability";
                this.ws = data.ws;

                // user-generated content
                this._attachments = evidence;
                this.data = data.data;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.name = data.name;
                this.owned = data.owned;
                this.parent = data.parent;
                this.refs = data.refs;
                this.resolution = data.resolution;
                this.severity = data.severity;
            },
            remove: function() {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id;
                return $http.delete(url);
            },
            update: function(data) {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id,
                vuln = new Vuln(self);
                vuln.set(data);
                return $http.put(url, vuln)
                    .success(function(response) {
                        self.set(data);
                        self._rev = response.rev;
                    });
            },
            save: function() {
                var self = this,
                url = BASEURL + self.ws + "/" + self._id,
                vuln = {};
                angular.extend(vuln, self);
                // remove WEBUI-specific fields
                delete vuln.date;
                delete vuln.delete;
                delete vuln.selected;
                delete vuln.web;
                delete vuln.ws;
                return $http.post(url, vuln)
                    .success(function(data) {
                        self._rev = data.rev;
                    });
            }
        }

        return Vuln;
    }]);
