// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('cweFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var cweFact = {};
        cweFact.cweList = [];

        // XXX: this is still not using the server
        cweFact.get = function() {
            var deferred = $q.defer();
            var cwe_url = BASEURL + 'cwe/_all_docs?include_docs=true';
            if (cweFact.cweList.length > 0) {
                deferred.resolve(cweFact.cweList);
            } else {
                $http.get(cwe_url).then(function(res) {
                    res.data.rows.forEach(function(obj) {
                        var description = "";

                        if(obj.doc.desc_summary) description += "Summary: " + obj.doc.desc_summary + "\n\n";
                        if(obj.doc.description) description += obj.doc.description;

                        var c = {
                            id: obj.id,
                            cwe: obj.doc.cwe,
                            name: obj.doc.name,
                            desc: description,
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
                        cweFact.cweList.push(c);
                    });
                    deferred.resolve(cweFact.cweList);
                });
            }

            return deferred.promise;
        };

        return cweFact;
    }]);
