// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('WebVuln', ['Vuln', 'BASEURL', '$http', function(Vuln, BASEURL, $http) {

        WebVuln = function(data) {
            Vuln.call(this, data);
            if(data) {
                this.set(data);
            }
        };

        WebVuln.prototype = new Vuln();

        WebVuln.prototype.set = function(data) {
                var id = CryptoJS.SHA1(data.name + "." + data.website + "." + data.path + "." + data.desc).toString();

                // new vuln
                if(data._id === undefined) {
                    data['_id'] = data.parent + "." + id;
                }

                this._id = data['_id'];
                this.obj_id = id;
                this.type = "VulnerabilityWeb";

                // user-generated content
                this.data = data.data;
                this.method = data.method;
                this.params = data.params;
                this.path = data.path;
                this.pname = data.pname;
                this.query = data.query;
                this.request = data.request;
                this.resolution = data.resolution;
                this.response = data.response;
                this.website = data.website;
        };

        return WebVuln;
    }]);
