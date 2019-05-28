// Faraday Penetration Test IDE
// Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('agentsCtrl', ['$scope', 'uuid', 'agentFact', 'Notification', '$routeParams', '$uibModal',
        function ($scope, uuid, agentFact, Notification, $routeParams, $uibModal) {
            $scope.agentToken = {id: null, token: null};
            $scope.workspace = null;
            $scope.agents = [];

            $scope.init = function () {
                $scope.workspace = $routeParams.wsId;
                getToken();
                getAgents();
            };


            var getToken = function () {
                agentFact.getAgentToken($scope.workspace).then(
                    function (response) {
                        if (response.data.length > 0)
                            $scope.agentToken = response.data[0];
                        else {
                            createToken();
                        }
                    }, function (error) {
                        console.log(error);
                    });
            };

            var createToken = function () {
                var agentToken = {'token': uuid.v4()};
                agentFact.createAgentToken(agentToken).then(
                    function (response) {
                        $scope.agentToken = response.data;
                    }, function (error) {
                        console.log(error);
                    });
            };

            var getAgents = function () {
                agentFact.getAgents($scope.workspace).then(
                    function (response) {
                        $scope.agents = response.data
                    }, function (error) {
                        console.log(error);
                    });
            };

            var removeAgentFromScope = function (agentId) {
                for (var i = 0; i < $scope.agents.length; i++) {
                    if ($scope.agents[i].id === agentId) {
                        $scope.agents.splice(i, 1);
                        break;
                    }
                }
            };

            $scope.refreshToken = function () {
                var agentToken = {id: $scope.agentToken.id, token: uuid.v4()};
                agentFact.updateAgentToken(agentToken).then(
                    function (response) {
                        $scope.agentToken = response.data;
                    }, function (error) {
                        console.log(error);
                    });
            };

            $scope.copyToClipboard = function () {
                var copyElement = document.createElement("textarea");
                copyElement.style.position = 'fixed';
                copyElement.style.opacity = '0';
                copyElement.textContent = decodeURI($scope.agentToken);
                var body = document.getElementsByTagName('body')[0];
                body.appendChild(copyElement);
                copyElement.select();
                document.execCommand('copy');
                body.removeChild(copyElement);
                Notification.success("Token " + $scope.agentToken.token + " copied to clipboard");
            };

            var _delete = function (agentId) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'md',
                    resolve: {
                        msg: function () {
                            return "A agent will be deleted. This action cannot be undone. " +
                                "Are you sure you want to proceed?";
                        }
                    }
                });

                modal.result.then(function () {
                    agentFact.deleteAgent($scope.workspace, agentId).then(
                        function (response) {
                            removeAgentFromScope(agentId);
                            Notification.success("The Agent has been removed");
                        }, function (error) {
                            console.log(error);
                        });
                });
            };

            $scope.removeAgent = function (agentId) {
                _delete(agentId);
            };

            $scope.changeStatusAgent = function (agent) {
                var oldStatus = agent.status;
                if (agent.status === 'paused')
                    agent.status = 'running';
                else
                    agent.status = 'paused';

                var agentData = {
                    id: agent.id,
                    status: agent.status
                };

                agentFact.updateAgent($scope.workspace, agentData).then(
                    function (response) {
                        if (response.data.status === 'paused')
                            Notification.success("The Agent has been paused");
                        else
                            Notification.success("The Agent is running");
                    }, function (error) {
                        agent.status = oldStatus;
                        console.log(error);
                    });
            };

            $scope.init();
        }]);
