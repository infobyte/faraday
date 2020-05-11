// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('customFieldFact', ['BASEURL', 'ServerAPI', '$http', '$q', function (BASEURL, ServerAPI, $http, $q) {
        var customFieldFact = {};

        customFieldFact.getCustomFields = function () {
            var deferred = $q.defer();
            ServerAPI.getCustomFields().then(function (response) {
                deferred.resolve(response)
            }, errorHandler);
            return deferred.promise;
        };


        errorHandler = function (response) {
            if (typeof(response) == "object")
                return $q.reject(response.data.reason.replace("file", "workspace"));
            else if (typeof(response) == "string")
                return $q.reject(response);
            else
                return $q.reject("Something bad happened");
        };

        customFieldFact.createCustomField = function (customField) {
            var deferred = $q.defer();
            ServerAPI.createCustomField(customField).then(function (response) {
                deferred.resolve(response)
            }, function (err) {
                deferred.reject(err);
            });
            return deferred.promise;
        };


        customFieldFact.updateCustomField = function (customField) {
            var deferred = $q.defer();
            ServerAPI.updateCustomField(customField).then(function (data) {
                customField._rev = data.rev;
                deferred.resolve(customField);
            }, function (err) {
                deferred.reject(err);
            });
            return deferred.promise;
        };

        customFieldFact.deleteCustomField = function(customFieldId) {
            var deferred = $q.defer();
            ServerAPI.deleteCustomField(customFieldId).then(function(response) {
                deferred.resolve(response);
            }, function() {
                deferred.reject();
            });
            return deferred.promise;
        };


        return customFieldFact;
    }]);
