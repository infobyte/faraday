// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('WebVuln', ['Vuln', 'BASEURL', '$http', function(Vuln, BASEURL, $http) {
        WebVuln = function(ws, data) {
            if(data) {
                if(data.name === undefined || data.name === "") {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(ws, data);
            }
        };

        var public_properties = [ 
            'method', 'params', 'path', 'pname', 'query',
            'request', 'response', 'website'
        ];

        WebVuln.prototype = new Vuln();

        WebVuln.prototype.public_properties = Vuln.prototype.public_properties.concat(public_properties);

        WebVuln.prototype.set = function(ws, data) {
            var self = this;

            Vuln.prototype.set.call(self, ws, data);

            // new vuln
            if(data._id === undefined) {
                var id = CryptoJS.SHA1(data.name + "." + data.website + "." + data.path + "." + data.desc).toString();

                self._id = data.parent + "." + id;
                self.obj_id = id;
            }

            self.type = "VulnerabilityWeb";

            public_properties.forEach(function(property) {
                if(data[property] !== undefined) self[property] = data[property];
            });
        };

        WebVuln.prototype.update = function(data) {
            var self = this,
            vuln = new WebVuln(self.ws, self);
            return Vuln.prototype._update.call(self, vuln, data);
        };

        WebVuln.prototype.populate = function() {
            var self = this,
            vuln = Vuln.prototype.populate.call(self);

            public_properties.forEach(function(property) {
                vuln[property] = self[property];
            });

            return vuln;
        };

        return WebVuln;
    }]);
