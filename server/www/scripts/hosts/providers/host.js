// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Host', ['BASEURL', 'ServerAPI', function(BASEURL, ServerAPI) {
        Host = function(data){
            this.set(data);
        };

        Host.prototype = {
            set: function(data) {
                var self = this;

                if(data._id != undefined) {
                    if(data.metadata !== undefined) self.metadata = data.metadata;
                }

                for (var key in data) {
                    if(data[key] !== undefined) self[key] = data[key];
                };
            },
            delete: function(ws) {
                return ServerAPI.deleteHost(ws, this.id);
            },

            update: function(data, ws) {
                var self = this;
                return ServerAPI.updateHost(ws, data);
            },

            save: function(ws) {
                var self = this;
                return ServerAPI.createHost(ws, self);
            },

        }
        return Host;
    }]);
