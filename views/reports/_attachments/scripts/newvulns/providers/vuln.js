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
                if(data._id === undefined) {
                    //data['_id'] = CryptoJS.SHA1(data.name).toString();
                    //// couch ID including parent id
                    //var id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                    //// object ID without parent
                    //var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                }
                var evidence = [],
                date = data.date * 1000;
                if(typeof(data.attachments) != undefined && data.attachments != undefined) {
                    for(var attachment in data.attachments) {
                        evidence.push(attachment);
                    }
                }
                    "meta":         {
                        'create_time': myEpoch,
                        "update_time": myEpoch,
                        "update_user":  'UI Web',
                        'update_action': 0,
                        'creator': 'UI Web', 
                        'create_time': myEpoch,
                        'update_controller_action': 'UI Web New',
                        'owner': 'anonymous'
                    },
                this._rev = data.rev;
                this._attachments = evidence;
                this.data = data.data;
                this.date = date;
                this.delete = false;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.metadata = data.metadata;
                this.name = data.name;
                this.obj_id = data.obj_id;
                this.owned = data.owned;
                this.owner = data.owner;
                this.parent = parent;
                this.refs = data.refs;
                this.resolution = data.resolution;
                this.selected = data.selected;
                this.severity = data.severity;
                this.type = "Vulnerability";
                this.web = false;
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
