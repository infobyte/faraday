// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnsByStatusCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.workspace = null;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getVulnerabilitiesGroupedBy($scope.workspace, 'status')
                        .then(function(vulnsByStatus) {
                          $scope.data = {key: [], value: [], colors: [], options: {maintainAspectRatio: false, animateRotate: true}};
                          $scope.loaded = true;

                          vulnerabilityColors = {
                            'open': '#DF3936',
                            'close': '#A1CE31',
                            're-open': '#DFBF35',
                            'risk-accept': '#2e97bd'
                          };

                          vulnsByStatus.forEach(function(vuln, index) {
                              $scope.data.value.push(vuln.count);
                              $scope.data.key.push(vuln.status);

                              $scope.data.colors.push(vulnerabilityColors[vuln.status]);
                          });

                          $scope.loaded = true;
                        });
                }
            };

            init();
    }]);
