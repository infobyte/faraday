// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('headerCtrl',
        ['$scope', '$routeParams', '$location', 'dashboardSrv', 'workspacesFact', 'vulnsManager',
        function($scope, $routeParams, $location, dashboardSrv, workspacesFact, vulnsManager) {

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
