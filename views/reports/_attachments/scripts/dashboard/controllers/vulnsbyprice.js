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

                /*
                $scope.prices = {
                    "critical": 1000,
                    "high": 500,
                    "med": 200,
                    "low": 100,
                    "info": 0,
                    "unclassified": 0
                };
                */

                $scope.prices = [
                    {"key": "critical", "value": 1000},
                    {"key": "high", "value": 500},
                    {"key": "med", "value": 200},
                    {"key": "low", "value": 100},
                    {"key": "info", "value": 0},
                    {"key": "unclassified", "value": 0}
                ];

                dashboardSrv.getVulnerabilities($scope.workspace).then(function(res) {
                    $scope.vulns = res;
                    $scope.generateData(res, $scope.prices);
                    $rootScope.$broadcast("vulnsByPriceDataReady");
                }); 

            };

            $scope.generateData = function(vulns, prices) {
                $scope.data = $scope.generatePrices(vulns, prices);
                $scope.total = $scope.generateTotal($scope.data);
            };

            $scope.generateTotal = function(prices) {
                var total = 0;

                prices.forEach(function(price) {
                    total += price.value;
                });

                return total;
            };

            $scope.generatePrices = function(vulns, prices) {
                var data =  [
                    {
                        color: '#932ebe',
                        value: 0,
                        key: 'critical'
                    }, {
                        color: '#DF3936',
                        value: 0,
                        key: 'high'
                    }, {
                        color: '#DFBF35',
                        value: 0,
                        key: 'med'
                    }, {
                        color: '#A1CE31',
                        value: 0,
                        key: 'low'
                    }, {
                        color: '#2e97bd',
                        value: 0,
                        key: 'info'
                    }, {
                        color: '#999999',
                        value: 0,
                        key: 'unclassified'
                    }
                ];

                pricesx = {};
                prices.forEach(function(price) {
                    pricesx[price.key] = price.value;
                });

                vulns.forEach(function(vuln) {
                    var sev = vuln.value.severity;

                    if(sev == 2 || sev == "low") {
                        dashboardSrv.accumulate(data, "low", pricesx[sev]);
                    } else if(sev == 3 || sev == "med") {
                        dashboardSrv.accumulate(data, "med", pricesx[sev]);
                    } else if(sev == 4 || sev == "high") {
                        dashboardSrv.accumulate(data, "high", pricesx[sev]);
                    } else if(sev == 5 || sev == "critical") {
                        dashboardSrv.accumulate(data, "critical", pricesx[sev]);
                    }
                });

                return data;
            };

            init();
        }]);
