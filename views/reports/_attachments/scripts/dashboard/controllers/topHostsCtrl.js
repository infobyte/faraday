// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('topHostsCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.topServices;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getTopServices($scope.workspace)
                        .then(function(services) {
                            $scope.topServices = {"children": services};
                        });
                }
            };

            $scope.treemap = function(data) {
                if(data !== undefined && data != {}) {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/dashboard/partials/modal-treemap.html',
                        controller: 'treemapModalCtrl',
                        size: 'lg',
                        resolve: {
                            workspace: function() {
                                return $scope.workspace;
                            }
                        }
                    });
                }
            };

            init();
    }]);