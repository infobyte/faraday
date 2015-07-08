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
                id = CryptoJS.SHA1(data.name + "." + data.desc).toString(),
                meta = {},
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
                    data['_id'] = data.parent + "." + id;
                    meta = {
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
                    this._rev = data._rev;
                    meta = {
                        "update_time": date,
                        "update_user":  data.meta.update_user,
                        "update_action": data.meta.update_action,
                        "creator": data.meta.creator,
                        "create_time": data.meta.create_time,
                        "update_controller_action": data.meta.update_controller_action,
                        "owner": data.meta.owner
                    };
                }

                this.date = date;
                this.metadata = meta;
                this.obj_id = id;
                this.owner = "";
                this.selected = selected;
                this.type = "Vulnerability";
                this.web = false;

                // user-generated content
                this._attachments = evidence;
                this.data = data.data;
                this.delete = false;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.name = data.name;
                this.owned = data.owned;
                this.parent = parent;
                this.refs = data.refs;
                this.resolution = data.resolution;
                this.severity = data.severity;
            },
            delete: function(ws) {
                var self = this;
                return $http.delete(BASEURL + ws + "/" + self._id);
            },
            update: function(data, ws) {
                var self = this;
                return $http.put(BASEURL + ws + "/" + self._id, data)
                    .success(function(data) {
                        self._rev = data.rev;
                    });
            },
            save: function(ws) {
                var self = this,
                vuln = {};
                angular.extend(vuln, self);
                // remove WEBUI-specific fields
                delete vuln.date;
                delete vuln.delete;
                delete vuln.selected;
                delete vuln.web;
                return $http.post(BASEURL + ws + "/" + self._id, vuln)
                    .success(function(data) {
                        self._rev = data.rev;
                    });
            }
        }

        return Vuln;
    }]);
