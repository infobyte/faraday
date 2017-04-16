// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('tagsFact', ['BASEURL', '$http', '$q', 'dashboardSrv',
        function(BASEURL, $http, $q, dashboardSrv) {
        var tagsFact = {};

        tagsFact.get = function(ws) {
            var tags;
            tags_url = BASEURL + 'cwe'

            // gets vulns json from couch
            $.getJSON(tags_url, function(data) {
                tags = data.rows;
            });
            return tags;
        }

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
