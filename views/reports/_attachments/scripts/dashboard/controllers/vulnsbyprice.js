// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsbypriceCtrl', 
        ['$scope', '$rootScope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $rootScope, $route, $routeParams, dashboardSrv) {
            init = function() {
                //current workspace
                $scope.workspace = $routeParams.wsId;

                $scope.vulnPrices = dashboardSrv.vulnPrices;

                dashboardSrv.getVulnerabilities($scope.workspace).then(function(res) {
                    $scope.vulns = res;
                    $scope.vulnsCount = $scope.generateVulnPrices(res, $scope.vulnPrices);
                    $scope.workspaceWorth = $scope.sumProperty($scope.vulnsCount, "amount");
                }); 

                $scope.$watch('vulnPrices', function(ps) {
                    if($scope.vulns != undefined) {
                        $scope.vulnsCount = $scope.generateVulnPrices($scope.vulns, $scope.vulnPrices);
                        $scope.workspaceWorth = $scope.sumProperty($scope.vulnsCount, "amount");
                    }
                }, true);
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

            $scope.generateVulnPrices = function(vulns, prices) {
                var data =  [
                    {
                        color: '#932ebe',
                        amount: 0,
                        key: 'critical'
                    }, {
                        color: '#DF3936',
                        amount: 0,
                        key: 'high'
                    }, {
                        color: '#DFBF35',
                        amount: 0,
                        key: 'med'
                    }, {
                        color: '#A1CE31',
                        amount: 0,
                        key: 'low'
                    }, {
                        color: '#2e97bd',
                        amount: 0,
                        key: 'info'
                    }, {
                        color: '#999999',
                        amount: 0,
                        key: 'unclassified'
                    }
                ];

                vulns.forEach(function(vuln) {
                    var sev = vuln.value.severity;

                    if(sev == 0 || sev == "unclassified") {
                        dashboardSrv.accumulate(data, "unclassified", parseInt(prices[sev]), "amount");
                    } else if(sev == 1 || sev == "info") {
                        dashboardSrv.accumulate(data, "info", parseInt(prices[sev]), "amount");
                    } else if(sev == 2 || sev == "low") {
                        dashboardSrv.accumulate(data, "low", parseInt(prices[sev]), "amount");
                    } else if(sev == 3 || sev == "med") {
                        dashboardSrv.accumulate(data, "med", parseInt(prices[sev]), "amount");
                    } else if(sev == 4 || sev == "high") {
                        dashboardSrv.accumulate(data, "high", parseInt(prices[sev]), "amount");
                    } else if(sev == 5 || sev == "critical") {
                        dashboardSrv.accumulate(data, "critical", parseInt(prices[sev]), "amount");
                    }
                });

                return data;
            };

            init();
        }]);
