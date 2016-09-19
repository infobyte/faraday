// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Host', ['BASEURL', '$http', function(BASEURL, $http) {
        Host = function(data){
            if(data) {
                this.set(data);
            }
        };

        Host.prototype = {
            // TODO: instead of using angular.extend, we should check
            // the attributes we're assigning to the host
            set: function(data) {
                // if there's no ID, we need to generate it based on the host name
                if(data._id === undefined){
                    data['_id'] = CryptoJS.SHA1(data.name).toString();
                }
                data.type = "Host";
                angular.extend(this, data);
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
                return $http.put(BASEURL + ws + "/" + self._id, JSON.stringify(self)).success(function(host_data){
                    $http.put(BASEURL + ws + "/" + interfaceData._id, JSON.stringify(interfaceData)).success(function(interface_data) {
                        self._rev = host_data.rev;
                        interfaceData._rev = interface_data.rev;
                    });
                });
            }
        }

        return Host;
    }]);
