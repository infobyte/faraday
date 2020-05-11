// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('dashboardCtrl',[
        '$scope',
        '$filter',
        '$route',
        '$routeParams',
        '$location',
        'dashboardSrv',
        'workspacesFact',
        'vulnsManager',
        'configSrv',
        function($scope,
                 $filter,
                 $route,
                 $routeParams,
                 $location,
                 dashboardSrv,
                 workspacesFact,
                 vulnsManager,
                 configSrv) {

            $scope.props = dashboardSrv.props;

            init = function() {
                //current workspace
                $scope.workspace = $routeParams.wsId;
                $scope.showVulnCost = configSrv.show_vulns_by_price;
                $scope.workspaces = [];
 
                workspacesFact.list().then(function(wss) {
                    $scope.workspaces = wss;
                });

                dashboardSrv.setConfirmedFromCookie();
                dashboardSrv.startTimer();
            };

            $scope.navigate = function(route) {
                $location.path(route);
            };

            $scope.$on('$destroy', function(){
                dashboardSrv.stopTimer();
            })

            $scope.reload = function() {
                dashboardSrv.updateData();
            }

            init();
    }]);
