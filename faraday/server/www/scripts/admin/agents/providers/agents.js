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
            $http.get(BASEURL + '_api/session').then(function(response){
                var fd = new FormData();
                fd.append('csrf_token', response.data.csrf_token);
                $http.post(BASEURL + '_api/v2/agent_token/', fd, {
                    transformRequest: angular.identity,
                    withCredentials: false,
                    headers: {'Content-Type': undefined},
                }).then(
                    function(tokenResponse) {
                        deferred.resolve(tokenResponse)
                    });
            });

            return deferred.promise;
        };


        agentFact.runAgent = function(wsName, agentId, executorData) {
            var deferred = $q.defer();
            $http.get(BASEURL +'_api/session').then(function(response){
                let data = {
                    'csrf_token': response.data.csrf_token,
                    'executorData': executorData
                };
                var postUrl = BASEURL + '_api/v2/ws/' + wsName + '/agents/' + agentId + '/run/';
                $http.post(postUrl, JSON.stringify(data), {
                    transformRequest: angular.identity,
                    withCredentials: false,
                    headers: {'Content-Type': 'application/json'}
                }).then(
                    function(tokenResponse) {
                        deferred.resolve(tokenResponse)
                    });
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
