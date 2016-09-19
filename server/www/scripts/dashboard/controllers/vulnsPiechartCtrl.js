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

                    $scope.loadData(true);

                    $scope.$watch(function() {
                        return dashboardSrv.props.confirmed;
                    }, function(newValue, oldValue) {
                        if (oldValue != newValue)
                            $scope.loadData(true);
                    }, true);
                }
            };

            $scope.loadData = function(animated) {
                dashboardSrv.getVulnerabilitiesCount($scope.workspace)
                    .then(function(vulns) {
                        $scope.data = {key: [], value: [], colors: [], options: {maintainAspectRatio: false, animateRotate: animated}};
                        $scope.loaded = true;
                        SEVERITIES.forEach(function(severity, index) {
                            if(severity != "unclassified" && vulns[severity] != undefined) {
                                $scope.data.value.push(vulns[severity]);
                                $scope.data.key.push(severity);
                                $scope.data.colors.push(dashboardSrv.vulnColors[index]);
                            }
                        });
                        // angular.copy(tmp, $scope.data);
                        //                    
                    });
            };

            dashboardSrv.registerCallback(function (){
                $scope.loadData(false);
            });

            init();
    }]);