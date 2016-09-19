// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('commandsCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.commands;
            $scope.cmdSortField = "date";
            $scope.cmdSortReverse = true;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getCommands($scope.workspace)
                        .then(function(commands) {
                            $scope.commands = commands;
                        });
                }
            };

            // toggles sort field and order
            $scope.cmdToggleSort = function(field) {
                $scope.cmdToggleSortField(field);
                $scope.cmdToggleReverse();
            };

            // toggles column sort field
            $scope.cmdToggleSortField = function(field) {
                $scope.cmdSortField = field;
            };

            // toggle column sort order
            $scope.cmdToggleReverse = function() {
                $scope.cmdSortReverse = !$scope.cmdSortReverse;
            }

            dashboardSrv.registerCallback(init);

            init();
    }]);