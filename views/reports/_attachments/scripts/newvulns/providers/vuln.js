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
                    data['_id'] = CryptoJS.SHA1(data.name).toString();
                    // couch ID including parent id
                    var id = $scope.target_selected._id + "." + CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                    // object ID without parent
                    var sha = CryptoJS.SHA1($scope.name + "." + $scope.desc).toString();
                }
                data.type = "Vulnerability";
                angular.extend(this, data);
                this.rev = data.rev;
                this.attachments = evidence;
                this.parent = ;
                this.data = data.data;
                this.delete = false;
                this.desc = data.desc;
                this.easeofresolution = data.easeofresolution;
                this.impact = data.impact;
                this.metadata = data.meta;
                this.name = data.name;
                this.obj_id = data.obj_id;
                this.owned = data.owned;
                this.owner = data.owner;
                this.refs = data.refs;
                this.resolution = data.resolution;
                this.selected = data.selected;
                this.severity = data.severity;
                this.type = data.type;
                this.web = false;
                this. = data.;
                this. = data.;
                this. = data.;


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
            },
            delete: function(ws) {
                var self = this,
                bulk = {docs:[]};
                return $http.get(BASEURL + ws + '/_all_docs?startkey="' + self._id + '"&endkey="' + self._id + '.z"').then(function(all) {
                    all.data.rows.forEach(function(row) {
                        bulk.docs.push({
                            "_id": row.id,
                            "_rev": row.value.rev,
                            "_deleted": true
                        });
                    });

                    return $http.post(BASEURL + ws + "/_bulk_docs", JSON.stringify(bulk));
                });
            },
            update: function(data, interfaceData, ws) {
                var self = this;
                bulk = {docs:[data,interfaceData]};
                return $http.post(BASEURL + ws + "/_bulk_docs", JSON.stringify(bulk)).success(function(data){
                    if(data.id == self._id){
                        self._rev = data.rev;
                    } else {
                        interfaceData._rev = data.rev;
                    }
                });
            },
            save: function(ws, interfaceData) {
                var self = this;
                bulk = {docs:[self,interfaceData]};
                return $http.post(BASEURL + ws + "/_bulk_docs", JSON.stringify(bulk)).success(function(data){
                    if(data.id == self._id){
                        self._rev = data.rev;
                    } else {
                        interfaceData._rev = data.rev;
                    }
                });
            }
        }

        return Vuln;
    }]);
