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
            // the attributes we're assigning to the user
            set: function(data) {
                // if there's no ID, we need to generate it based on the host name
                if(data._id === undefined){
                    data['_id'] = CryptoJS.SHA1(data.name).toString();
                }
                data.type = "Host";
                angular.extend(this, data);
            },
            delete: function(ws) {
                var self = this;
                return ($http.delete(BASEURL + ws + '/' + self._id + "?rev=" + self._rev));
            },
            update: function(data, ws) {
                var self = this;
                angular.extend(this, data);

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

        return Host;
    }]);
