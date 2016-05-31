// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsPiechartCtrl',
        ['$scope', '$routeParams', 'dashboardSrv', 'SEVERITIES',
        function($scope, $routeParams, dashboardSrv, SEVERITIES) {

            $scope.data;
            $scope.loaded = false;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    $scope.data = {key: [], value: [], colors: [], options: {maintainAspectRatio: false}};

                    dashboardSrv.getVulnerabilitiesCount($scope.workspace)
                        .then(function(vulns) {
                            $scope.loaded = true;
                            SEVERITIES.forEach(function(severity, index) {
                                if(severity != "unclassified" && vulns[severity] != undefined) {
                                    $scope.data.value.push(vulns[severity]);
                                    $scope.data.key.push(severity);
                                    $scope.data.colors.push(dashboardSrv.vulnColors[index]);
                                }
                            });
                        });
                }
            };

            init();
    }]);