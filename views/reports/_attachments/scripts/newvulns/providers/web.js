// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('WebVuln', ['BASEURL', '$http', function(BASEURL, $http) {
        WebVuln = function(data){
            if(data) {
                this.set(data);
            }
        };

        WebVuln.prototype = {
            set: function(data) {
                if(data._id === undefined) {
                    data['_id'] = CryptoJS.SHA1(data.name).toString();
                    //// couch ID including parent id
                    //var id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                    //// object ID without parent
                    //var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                }
                var evidence = [],
                date = obj.value.date * 1000;
                if(typeof(obj.value.attachments) != undefined && obj.value.attachments != undefined) {
                    for(var attachment in obj.value.attachments) {
                        evidence.push(attachment);
                    }
                }
                this._rev = data.rev;
                this._attachments = evidence;
                this.data = data.data;
                this.date = date;
                this.delete = false;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.metadata = data.metadata;
                this.method = data.method;
                this.name = data.name;
                this.obj_id = data.obj_id;
                this.owned = data.owned;
                this.owner = data.owner;
                this.params = data.params;
                this.parent = parent;
                this.path = path;
                this.pname = pname;
                this.query = query;
                this.refs = data.refs;
                this.request = request;
                this.resolution = data.resolution;
                this.response = response;
                this.selected = data.selected;
                this.severity = data.severity;
                this.type = "VulnerabilityWeb";
                this.web = true;
                this.website = data.website;
            },
            delete: function(ws) {
                var self = this;
                return $http.delete(BASEURL + ws + "/" + self._id);
            },
            update: function(data, ws) {
                var self = this;
                return $http.post(BASEURL + ws + "/" + self._id, data)
                    .success(function(data) {
                        if(data.id == self._id){
                            self._rev = data.rev;
                        }
                    });
            },
            save: function(ws) {
                var self = this,
                vuln = {};
                angular.extend(vuln, self);
                // remove UI-specific fields
                delete vuln.date;
                delete vuln.delete;
                delete vuln.selected;
                delete vuln.web;
                return $http.post(BASEURL + ws + "/" + self._id, vuln)
                    .success(function(data) {
                        if(data.id == self._id){
                            self._rev = data.rev;
                        }
                    });
            }
        }

        return WebVuln;
    }]);
/*
// Will this work?
    .factory('WebVuln', ['Vuln', 'BASEURL', '$http', function(Vuln, BASEURL, $http) {
        WebVuln = Object.create(Vuln);

        WebVuln = function(data) {
            if(data) {
                this.set(data);
            }
        };

        WebVuln.prototype = {
            set: function(data) {
                if(data._id === undefined) {
                    data['_id'] = CryptoJS.SHA1(data.name).toString();
                    //// couch ID including parent id
                    //var id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                    //// object ID without parent
                    //var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                }
                var evidence = [],
                date = obj.value.date * 1000;
                if(typeof(obj.value.attachments) != undefined && obj.value.attachments != undefined) {
                    for(var attachment in obj.value.attachments) {
                        evidence.push(attachment);
                    }
                }
                this._rev = data.rev;
                this._attachments = evidence;
                this.data = data.data;
                this.date = date;
                this.delete = false;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.metadata = data.metadata;
                this.method = data.method;
                this.name = data.name;
                this.obj_id = data.obj_id;
                this.owned = data.owned;
                this.owner = data.owner;
                this.params = data.params;
                this.parent = parent;
                this.path = path;
                this.pname = pname;
                this.query = query;
                this.refs = data.refs;
                this.request = request;
                this.resolution = data.resolution;
                this.response = response;
                this.selected = data.selected;
                this.severity = data.severity;
                this.type = "VulnerabilityWeb";
                this.web = true;
                this.website = data.website;
            }
        }

        return WebVuln;
    }]);
*/
