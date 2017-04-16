// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('tagsFact', ['BASEURL', '$http', '$q', 'dashboardSrv',
        function(BASEURL, $http, $q, dashboardSrv) {
        var tagsFact = {};

        tagsFact.get = function(ws) {
            var tags;
            tags_url = BASEURL + ws +"/_design/tags/_view/tag";

            if(dashboardSrv.props['confirmed']) {
                tags_url += "confirmed";
            }

            tags_url += "?group=true";

            // gets vulns json from couch
            $.getJSON(tags_url, function(data) {
                tags = data.rows;
            });
            return tags;
        }

        tagsFact.getCloud = function(ws) {
            var deferred = $q.defer(),
            url = BASEURL + ws + "/_design/tags/_view/tag";

            if(dashboardSrv.props['confirmed']) {
                url += "confirmed";
            }

            url += "?group=true";

            $http.get(url)
                .then(function(resp) {
                    var cant = 0,
                    tags = resp.data.rows,
                    ts = [];

                    tags.forEach(function(tag) {
                        cant += tag.value;
                    });

                    tags.forEach(function(tag) {
                        ts.push({
                            "key": tag.key,
                            "value": tag.value,
                            "perc": 100 * tag.value / cant
                        });
                    });

                    ts.sort(function(a, b) {
                        return b.value - a.value;
                    });

                    deferred.resolve(ts);
                }, function() {
                    deferred.reject("Unable to retrieve Tags from DB");
                });

            return deferred.promise;
        };

        tagsFact.getById = function(ws, id){
            var object;
            object_url = BASEURL + ws + "/" + id;
            $.getJSON(object_url, function(data) {
                object = data;
            });
            return object;
        };

        // receives workspace to update
        // original AngularJS's model obj
        // tags to set on obj
        // callback to execute afterwards
        tagsFact.put = function(ws, obj, tags, callback){
            // using obj we need to get the obj as it is on the DB
            var couchObj = tagsFact.getById(ws, obj.id),
            url = BASEURL + ws + "/" + obj.id;
            // we set the tags to the DB obj
            couchObj.tags = tags;

            // aaand we save it to de DB
            $http.put(url, couchObj).success(function(d, s, h, c) {
                callback(d.rev);
                // also, please update the original AngulaJS's obj's tags
                // please remember that this obj belongs to the status report's scope
                obj.tags = tags;
            });
        };

        return tagsFact;
    }]);
