// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('dashboardCtrl',
        ['$scope', '$filter', '$route', '$routeParams', '$location', 'dashboardSrv', 'workspacesFact',
        function($scope, $filter, $route, $routeParams, $location, dashboardSrv, workspacesFact) {
            $scope.props = dashboardSrv.props;

            init = function() {
                //current workspace
                $scope.workspace = $routeParams.wsId;
                $scope.workspaces = [];

                workspacesFact.list().then(function(wss) {
                    $scope.workspaces = wss;
                });
            };

            $scope.navigate = function(route) {
                $location.path(route);
            };

            $scope.toggleConfirmed = function() {
                dashboardSrv.setConfirmed();
            };

            init();
    }]);
