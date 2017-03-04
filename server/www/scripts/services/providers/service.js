// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('Service', ['BASEURL', 'ServerAPI', function(BASEURL, ServerAPI) {
        Service = function(data) {
            if(data) {
                this.set(data);
            }
        };

        var public_properties = [
            'description', 'name', 'owned', 'ports', 'protocol',
            'status', 'version'
        ];

        var saved_properties = public_properties.concat(
            ['_id', '_rev', 'metadata', 'owner', 'parent', 'type']);

        Service.prototype = {
            public_properties: public_properties,
            saved_properties: saved_properties,
            // TODO: instead of using angular.extend, we should check
            // the attributes we're assigning to the Service
            set: function(data) {
                // if there's no ID, we need to generate it based on the Service name
                if(data._id === undefined) {
                    var ports = data.ports;

                    if(typeof data.ports == "object") {
                        ports = ports.toString().replace(/,/g,":");
                    }

                    data['_id'] = data.parent + "." + CryptoJS.SHA1(data.protocol+ "._." + ports).toString();
                }
                data.type = "Service";
                angular.extend(this, data);
                if( typeof(data.ports) === 'number' ) {
                    this.ports = data.ports;
                } else {
                    this.ports = data.ports[0];
                }
            },

            delete: function(ws) {
                return ServerAPI.deleteService(ws, this._id, this._rev);
            },

            update: function(data, ws) {
                angular.extend(this, data);
                var self = this;

                if(typeof self.ports != "object") {
                    self.ports = [self.ports];
                }

                return (self._save(ws, self, true).then(
                    function(data) {
                        self._rev = data.rev;
                }));
            },
            save: function(ws) {
                var self = this;

                if(typeof self.ports != "object") {
                    self.ports = [self.ports];
                }

                return (self._save(ws, self, false).then(
                    function(data){
                        self._rev = data.rev;
                }));
            },
            _save: function(ws, data, isUpdate) {
                if (typeof isUpdate === 'undefined') {isUpdate = false};
                doc = {};
                for (property in data) {
                    if (this.saved_properties.indexOf(property) != -1) {
                        doc[property] = data[property];
                    }
                }

                if (isUpdate) {
                    return ServerAPI.updateService(ws, doc);
                } else {
                    return ServerAPI.createService(ws, doc);
                }
            }
        }

        return Service;
    }]);
