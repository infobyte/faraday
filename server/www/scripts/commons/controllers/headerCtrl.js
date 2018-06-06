// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('headerCtrl',
        ['$scope', '$routeParams', '$location', '$cookies', 'dashboardSrv', 'workspacesFact', 'vulnsManager',
        function($scope, $routeParams, $location, $cookies, dashboardSrv, workspacesFact, vulnsManager) {
            $scope.confirmed = ($cookies.get('confirmed') == undefined) ? false : JSON.parse($cookies.get('confirmed'));

            $scope.showSwitcher = function() {
                var noSwitcher = ["", "home", "login", "index", "vulndb", "credentials", "workspaces", "users", "licenses"];
                return noSwitcher.indexOf($scope.component) < 0;
            };

            $scope.getVulnsNum = function() {
                return vulnsManager.getVulnsNum();
            };

            $scope.toggleConfirmed = function() {
                $scope.confirmed = !$scope.confirmed;
                dashboardSrv.setConfirmed($scope.confirmed);
                dashboardSrv.updateData();
            };

            init = function(name) {
                $scope.location = $location.path().split('/')[1];
                $scope.workspace = $routeParams.wsId;
                $scope.workspaces = [];

                workspacesFact.list().then(function(wss) {
                    $scope.workspaces = wss;
                });
            };

            init();
    }]);
