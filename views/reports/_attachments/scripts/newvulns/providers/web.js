// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('WebVuln', ['Vuln', 'BASEURL', '$http', function(Vuln, BASEURL, $http) {

        WebVuln = function(data) {
            if(data) {
                if(data.name === "" || data.name === undefined) {
                    throw new Error("Unable to create Vuln without a name");
                }
                this.set(data);
            }
        };

        WebVuln.prototype = new Vuln();

        WebVuln.prototype.set = function(data) {
            Vuln.prototype.set.call(this, data);
            this._id = data._id;
            this.obj_id = data._id;

            // new vuln
            if(data._id === undefined) {
                var id = CryptoJS.SHA1(data.name + "." + data.website + "." + data.path + "." + data.desc).toString();

                //data['_id'] = data.parent + "." + id;
                this._id = data.parent + "." + id;
                this.obj_id = id;
            }

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
