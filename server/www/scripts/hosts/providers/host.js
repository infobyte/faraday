// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Host', ['BASEURL', 'ServerAPI', function(BASEURL, ServerAPI) {
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
                return ServerAPI.deleteHost(ws, this._id, this.rev);
            },

            update: function(data, interfaceData, ws) {
                var self = this;
                return ServerAPI.updateHost(ws, data)
                .then(function(data) {
                    if(data.id == self._id) {
                        self._rev = data.rev;
                    } else {
                        interfaceData._rev = data.rev;
                    }
                });
            },

            save: function(ws, interfaceData) {
                var self = this;
                return ServerAPI.createHost(ws, self).
                    then(function(host_data) {
                        ServerAPI.createInterface(ws, interfaceData).
                        then(function(interface_data) {
                            self._rev = host_data.rev;
                            interfaceData._rev = interface_data.rev;
                        });
                    });
            },

        }
        return Host;
    }]);
