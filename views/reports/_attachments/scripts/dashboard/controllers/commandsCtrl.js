// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('commandsCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.commands;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getCommands($scope.workspace)
                        .then(function(commands) {
                            $scope.commands = commands;
                        });
                }
            };

            init();
    }]);