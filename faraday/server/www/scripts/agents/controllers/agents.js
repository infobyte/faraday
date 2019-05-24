// Faraday Penetration Test IDE
// Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('agentsCtrl', ['$scope', 'uuid', 'agentFact', 'Notification', '$routeParams',
        function ($scope, uuid, agentFact, Notification, $routeParams) {
            $scope.newToken = null;
            $scope.workspace = null;
            $scope.agents = [];

            $scope.init = function () {
                $scope.workspace = $routeParams.wsId;
                $scope.newToken = uuid.v4();
                getAgents();
            };

            var getAgents = function () {
                agentFact.getAgents($scope.workspace).then(
                    function (response) {
                       $scope.agents = response.data
                    }, function (error) {
                        console.log(error);
                    });
            };

            var copyToClipboard = function (token) {
                var copyElement = document.createElement("textarea");
                copyElement.style.position = 'fixed';
                copyElement.style.opacity = '0';
                copyElement.textContent = decodeURI(token);
                var body = document.getElementsByTagName('body')[0];
                body.appendChild(copyElement);
                copyElement.select();
                document.execCommand('copy');
                body.removeChild(copyElement);
            };

            $scope.refreshToken = function () {
                $scope.newToken = uuid.v4();
            };

            $scope.acceptToken = function () {
                var agentToken = {'token': $scope.newToken};
                agentFact.createAgentToken(agentToken).then(
                    function (response) {
                        copyToClipboard($scope.newToken);
                        Notification.success("Token " + $scope.newToken + " copied to clipboard");
                        $scope.newToken = uuid.v4();
                    }, function (error) {
                        console.log(error);
                    });
            };

            $scope.init();
        }]);
