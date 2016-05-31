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

                    vulnsManager.getVulns($scope.workspace)
                        .then(function(vulns) {
                            $scope.vulns = vulnsManager.vulns;
                        });
                }
            };

            init();
    }]);