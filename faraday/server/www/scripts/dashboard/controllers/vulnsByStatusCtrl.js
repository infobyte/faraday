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
                    $scope.loadData();

                    $scope.$watch(function() {
                        return dashboardSrv.props.confirmed;
                    }, function(newValue, oldValue) {
                        if (oldValue != newValue)
                            $scope.loadData();
                    }, true);
                }
            };

            $scope.loadData = function(){
                dashboardSrv.getVulnerabilitiesGroupedBy($scope.workspace, 'status', dashboardSrv.props.confirmed)
                    .then(function(vulnsByStatus) {
                      $scope.data = {key: [], value: [], colors: [], options: {maintainAspectRatio: false, animateRotate: true}};
                      $scope.loaded = true;

                      vulnerabilityColors = {
                        'open': '#e77273',
                        'closed': '#bddd72',
                        're-opened': '#e7d174',
                        'risk-accepted': '#7aabd9'
                      };

                      vulnsByStatus.forEach(function(vuln, index) {
                          $scope.data.value.push(vuln.count);
                          $scope.data.key.push(vuln.status);

                          $scope.data.colors.push(vulnerabilityColors[vuln.status]);
                      });

                      $scope.loaded = true;
                    });
            }

            dashboardSrv.registerCallback($scope.loadData);
            init();
    }]);
