// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('cweFact', ['BASEURL', '$http', '$q', 'vulnModelsManager', 'commonsFact', function(BASEURL, $http, $q, vulnModelsManager, commonsFact) {
        var cweFact = {};

        // XXX: this is still not using the server
        cweFact.get = function() {
            var cweList = [];
            var deferred = $q.defer();
            var cwe_url = BASEURL + 'cwe/_all_docs?include_docs=true';
            $http.get(cwe_url).then(function(res) {
                res.data.rows.forEach(function(obj) {
                    var description = "";

                    if(obj.doc.description) description += obj.doc.description;

                    var c = {
                        id: obj.id,
                        cwe: obj.doc.cwe,
                        name: commonsFact.htmlentities(obj.doc.name),
                        desc: commonsFact.htmlentities(description),
                        resolution: obj.doc.resolution,
                        exploitation: obj.doc.exploitation,
                        refs: obj.doc.references
                    };
                    if (typeof(obj.doc.references) == "string") {
                        c.refs = [];
                        obj.doc.references.split('\n').forEach(function(ref) {
                            if (ref != "") {
                                c.refs.push(ref);
                            }
                        });
                    }
                    cweList.push(c);
                });
                deferred.resolve(cweList);
            });
            return deferred.promise;
        };

        return cweFact;
    }]);
