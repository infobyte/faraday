// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('agentFact', ['BASEURL', 'ServerAPI', '$http', '$q', function(BASEURL, ServerAPI, $http, $q) {
        var agentFact = {};

        agentFact.getAgentToken = function() {
            var deferred = $q.defer();
            ServerAPI.getAgentToken().then(function(response) {
                    deferred.resolve(response);
                }, function (error) {
                deferred.reject(error)
            });
            return deferred.promise;
        };

        agentFact.getNewAgentToken = function() {
            var deferred = $q.defer();
            ServerAPI.getNewAgentToken().then(function(response) {
                    deferred.resolve(response);
                }, function (error) {
                deferred.reject(error)
            });
            return deferred.promise;
        };

        agentFact.getAgents = function(wsName) {
            var deferred = $q.defer();
            ServerAPI.getAgents(wsName).then(function(response) {
                    deferred.resolve(response);
                }, function (error) {
                deferred.reject(error)
            });
            return deferred.promise;
        };

        agentFact.deleteAgent = function(wsName, agentId) {
            var deferred = $q.defer();
            ServerAPI.deleteAgent(wsName, agentId).then(function(response) {
                    deferred.resolve(response);
                }, function (error) {
                deferred.reject(error)
            });
            return deferred.promise;
        };

        agentFact.updateAgent = function(wsName, agent) {
            var deferred = $q.defer();
            ServerAPI.updateAgent(wsName, agent).then(function(response) {
                    deferred.resolve(response);
                }, function (error) {
                deferred.reject(error)
            });
            return deferred.promise;
        };

        return agentFact;
    }]);
