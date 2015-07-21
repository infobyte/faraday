// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Vuln', ['BASEURL', '$http', function(BASEURL, $http) {
        Vuln = function(data){
            if(data) {
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

                if(typeof(data.attachments) != undefined && data.attachments != undefined) {
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
                    metadata = {
                        "update_time": date,
                        "update_user": "",
                        "update_action": 0,
                        "creator": "UI Web",
                        "create_time": date,
                        "update_controller_action": "UI Web New",
                        "owner": ""
                    };
                } else {
                    if(data.selected != undefined) {
                        selected = data.selected;
                    }
                    this._id = data._id;
                    this._rev = data._rev;
                    this.obj_id = data._id;
                    metadata = {
                        "update_time": date,
                        "update_user":  data.metadata.update_user,
                        "update_action": data.metadata.update_action,
                        "creator": data.metadata.creator,
                        "create_time": data.metadata.create_time,
                        "update_controller_action": data.metadata.update_controller_action,
                        "owner": data.metadata.owner
                    };
                }

                this.date = date;
                this.delete = false;
                this.metadata = metadata;
                this.owner = "";
                this.selected = selected;
                this.type = "Vulnerability";
                this.web = false;
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
