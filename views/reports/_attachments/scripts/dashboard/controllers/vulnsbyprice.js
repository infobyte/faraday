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

                $scope.prices = {
                    "critical": "5000",
                    "high": "3000",
                    "med": "1000",
                    "low": "500",
                    "info": "0",
                    "unclassified": "0"
                };

                dashboardSrv.getVulnerabilities($scope.workspace).then(function(res) {
                    $scope.vulns = res;
                    $scope.generateData(res, $scope.prices);
                }); 

                $scope.$watch('prices', function(ps) {
                    if($scope.vulns != undefined) $scope.generateData($scope.vulns, ps);
                }, true);
            };

            $scope.generateData = function(vulns, prices) {
                $scope.data = $scope.generatePrices(vulns, prices);
                $scope.total = $scope.generateTotal($scope.data);
            };

            $scope.generateTotal = function(data) {
                var total = 0;

                for(var d in data) {
                    if(data.hasOwnProperty(d)) {
                        total += parseInt(data[d]['value']);
                    }
                }

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

                vulns.forEach(function(vuln) {
                    var sev = vuln.value.severity;

                    if(sev == 0 || sev == "unclassified") {
                        dashboardSrv.accumulate(data, "unclassified", parseInt(prices[sev]));
                    } else if(sev == 1 || sev == "info") {
                        dashboardSrv.accumulate(data, "info", parseInt(prices[sev]));
                    } else if(sev == 2 || sev == "low") {
                        dashboardSrv.accumulate(data, "low", parseInt(prices[sev]));
                    } else if(sev == 3 || sev == "med") {
                        dashboardSrv.accumulate(data, "med", parseInt(prices[sev]));
                    } else if(sev == 4 || sev == "high") {
                        dashboardSrv.accumulate(data, "high", parseInt(prices[sev]));
                    } else if(sev == 5 || sev == "critical") {
                        dashboardSrv.accumulate(data, "critical", parseInt(prices[sev]));
                    }
                });

                return data;
            };

            init();
        }]);
