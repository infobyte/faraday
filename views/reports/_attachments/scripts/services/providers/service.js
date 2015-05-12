// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Service', ['BASEURL', '$http', function(BASEURL, $http) {
        Service = function(data){
            if(data) {
                this.set(data);
            }
        };

        Service.prototype = {
            // TODO: instead of using angular.extend, we should check
            // the attributes we're assigning to the Service
            set: function(data) {
                // if there's no ID, we need to generate it based on the Service name
                if(data._id === undefined){
                    var ports = data.ports.toString().replace(/,/g,":");
                    data['_id'] = data.parent + "." + CryptoJS.SHA1(data.protocol+ "._." + ports).toString();
                }
                data.type = "Service";
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
            update: function(data, ws) {
                angular.extend(this, data);
                var self = this;

                return ($http.put(BASEURL + ws + '/' + self._id + "?rev=" + self._rev, self).success(function(data) {
                    self._rev = data.rev;
                }));
            },
            save: function(ws) {
                var self = this;
                return ($http.put(BASEURL + ws + '/' + self._id, self).success(function(data){
                    self._rev = data.rev;
                }));
            }
        }

        return Service;
    }]);
