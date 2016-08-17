// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsByPriceCtrl',
        ['$scope', '$routeParams', 'dashboardSrv', 'SEVERITIES',
        function($scope, $routeParams, dashboardSrv, SEVERITIES) {

            $scope.vulnPrices;
            $scope.vulns;
            $scope.workspace;
            $scope.workspaceWorth = 0;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;
                    $scope.vulnPrices = dashboardSrv.vulnPrices;

                    $scope.loadData();

                    $scope.$watch('vulnPrices', function(ps) {
                        if($scope.vulns != undefined) {
                            $scope.generateVulnPrices($scope.vulns, $scope.vulnPrices);
                            $scope.workspaceWorth = $scope.sumProperty($scope.vulns, "amount");
                        }
                    }, true);

                    $scope.$watch(function() {
                        return dashboardSrv.props.confirmed;
                    }, function(newValue, oldValue) {
                        if (oldValue != newValue)
                            $scope.loadData();
                    }, true);
                }
            };

            $scope.generateVulnPrices = function(vulns, prices) {
                vulns.forEach(function(vuln) {
                    vuln.amount = vuln.value * prices[vuln.key];
                });
            };

            $scope.loadData = function() {
                dashboardSrv.getVulnsWorth($scope.workspace)
                    .then(function(vulns) {
                        $scope.vulns = vulns;
                        $scope.generateVulnPrices($scope.vulns, $scope.vulnPrices);
                        $scope.workspaceWorth = $scope.sumProperty($scope.vulns, "amount");
                    });
            };

            $scope.sumProperty = function(data, prop) {
                var total = 0;

                for(var d in data) {
                    if(data.hasOwnProperty(d)) {
                        if(data[d][prop] !== undefined) total += parseInt(data[d][prop]);
                    }
                }

                return total;
            };

            init();
    }]);