// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsBySeverityCtrl',
        ['$scope', '$routeParams', 'dashboardSrv', 'SEVERITIES',
        function($scope, $routeParams, dashboardSrv, SEVERITIES) {

            $scope.vulns = {};
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getVulnerabilitiesCount($scope.workspace)
                        .then(function(vulns) {
                            SEVERITIES.forEach(function(severity) {
                                $scope.vulns[severity] = vulns[severity] || 0;
                            });
                        });
                }
            };

            init();
    }]);