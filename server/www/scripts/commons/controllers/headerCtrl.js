// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('headerCtrl',
        ['$scope', '$routeParams', '$location', 'dashboardSrv', 'workspacesFact', 'vulnsManager',
        function($scope, $routeParams, $location, dashboardSrv, workspacesFact, vulnsManager) {


            $scope.showHeader = function() {
                var noNav = ["", "home", "login", "index"];
                return noNav.indexOf($scope.component) < 0;
            };

            init = function(name) {
                $scope.location = $location.path().split('/')[1];
                $scope.workspace = $routeParams.wsId;
                $scope.workspaces = [];

                workspacesFact.list().then(function(wss) {
                    $scope.workspaces = wss;
                });

                vulnsManager.getVulns($scope.workspace, null, null, null, null, null)
                    .then(function(response) {
                        $scope.totalItems = response.count;
                    });
            };

            init();
    }]);
