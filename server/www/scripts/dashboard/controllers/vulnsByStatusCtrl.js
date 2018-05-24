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
                          vulnsByStatus.forEach(function(vuln, index) {
                              $scope.data.value.push(vuln.count);
                              $scope.data.key.push(vuln.status);
                              $scope.data.colors.push(dashboardSrv.vulnColors[index]);
                          });

                          $scope.loaded = true;
                        });
                }
            };

            dashboardSrv.registerCallback(init);

            init();
    }]);
