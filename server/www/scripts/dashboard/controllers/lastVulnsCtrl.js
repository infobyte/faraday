// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('lastVulnsCtrl',
        ['$scope', '$routeParams', 'dashboardSrv', 'vulnsManager',
        function($scope, $routeParams, dashboardSrv, vulnsManager) {
            $scope.vulns;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    $scope.loadData();

                    $scope.$watch(function() {
                        return dashboardSrv.props.confirmed;
                    }, function() {
                        $scope.loadData();
                    }, true);
                }
            };

            $scope.loadData = function() {
                var filter = {};
                if (dashboardSrv.props.confirmed) {
                    filter.confirmed = true;
                }
                vulnsManager.getVulns($scope.workspace, 0, 5, filter, "date", "desc")
                    .then(function(res) {
                        $scope.vulns = res.vulnerabilities;
                    });
            };

            init();
    }]);