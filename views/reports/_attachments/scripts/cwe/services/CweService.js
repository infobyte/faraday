// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('cweFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var cweFact = {};
        cweFact.cweList = [];

        cweFact.get = function() {
            var deferred = $q.defer();
            var cwe_url = BASEURL + 'cwe/_all_docs?include_docs=true';

            $http.get(cwe_url).then(function(res) {
                res.data.rows.forEach(function(obj) {
                    var c = {
                        id: obj.id,
                        cwe: obj.doc.cwe,
                        name: obj.doc.name,
                        desc: "Summary: " + obj.doc.desc_summary + "\n\n" + obj.doc.description,
                        resolution: obj.doc.resolution,
                        exploitation: obj.doc.exploitation,
                        references: obj.doc.references
                    };
                    cweFact.cweList.push(c);
                });
                deferred.resolve(cweFact.cweList);
            });

            return deferred.promise;
        };

        return cweFact;
    }]);
