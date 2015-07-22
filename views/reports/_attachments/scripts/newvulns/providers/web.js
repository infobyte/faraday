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

        WebVuln.prototype = new Vuln();

        WebVuln.prototype.set = function(ws, data) {
            Vuln.prototype.set.call(this, ws, data);
            // new vuln
            if(data._id === undefined) {
                var id = CryptoJS.SHA1(data.name + "." + data.website + "." + data.path + "." + data.desc).toString();

                this._id = data.parent + "." + id;
                this.obj_id = id;
            } else {
                this._id = data._id;
                this.obj_id = data._id;
            }

            this.type = "VulnerabilityWeb";

            // user-generated content
            if(data.method !== undefined) this.method = data.method;
            if(data.params !== undefined) this.params = data.params;
            if(data.path !== undefined) this.path = data.path;
            if(data.pname !== undefined) this.pname = data.pname;
            if(data.query !== undefined) this.query = data.query;
            if(data.request !== undefined) this.request = data.request;
            if(data.resolution !== undefined) this.resolution = data.resolution;
            if(data.response !== undefined) this.response = data.response;
            if(data.website !== undefined) this.website = data.website;
        };

        return WebVuln;
    }]);
