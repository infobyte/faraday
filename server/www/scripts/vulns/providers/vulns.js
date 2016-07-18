// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('vulnsManager',
        ['Vuln', 'WebVuln', 'BASEURL', '$http', '$q', 'commonsFact',
        function(Vuln, WebVuln, BASEURL, $http, $q, commonsFact) {
        var vulnsManager = {};

        vulnsManager.createVuln = function(ws, data) {
            if(data.type == "Vulnerability") {
                var vuln = new Vuln(ws, data);
            } else {
                var vuln = new WebVuln(ws, data);
            }

            return vuln.save();
        };

        vulnsManager.deleteVuln = function(vuln) {
            return vuln.remove();
        };

        vulnsManager.getVulns = function(ws, page, page_size, filter, sort, sort_direction) {
            var deferred = $q.defer();

            var url = BASEURL + '_api/ws/' + ws + '/vulns';
            url = commonsFact.addPresentationParams(url, page, page_size, filter, sort, sort_direction);

            $http.get(url)
                .then(function(response) {
                    var result = {
                        vulnerabilities: [],
                        count: 0
                    };

                    for(var i = 0; i < response.data.vulnerabilities.length; i++) {
                        var vulnData = response.data.vulnerabilities[i].value;
                        try {
                            if(vulnData.type == "Vulnerability") {
                                var vuln = new Vuln(ws, vulnData);
                            } else {
                                var vuln = new WebVuln(ws, vulnData);
                            }
                            result.vulnerabilities.push(vuln);
                        } catch(e) {
                            console.log(e.stack);
                        }
                    }

                    result.count = response.data.count
                    deferred.resolve(result);
                }, function(response) {
                    deferred.reject("Unable to retrieve vulnerabilities from server");
                });

            return deferred.promise;
        };

        vulnsManager.updateVuln = function(vuln, data) {
            return vuln.update(data);
        };

        return vulnsManager;

    }]);
