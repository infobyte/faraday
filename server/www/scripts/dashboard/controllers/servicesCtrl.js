// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('servicesCtrl',
        ['$scope', '$uibModal', '$routeParams', 'dashboardSrv',
        function($scope, $uibModal, $routeParams, dashboardSrv) {
            $scope.servicesCount;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getServicesCount($scope.workspace)
                        .then(function(services) {
                            $scope.servicesCount = services;
                        });
                }
            };

            $scope.showHosts = function(srv_name) {
                if($scope.workspace != undefined) {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/dashboard/partials/modal-hosts-by-service.html',
                        controller: 'summarizedCtrlHostsModal',
                        size: 'lg',
                        resolve: {
                            srv_name: function() {
                                return srv_name;
                            },
                            workspace: function() {
                                return $scope.workspace;
                            }
                        }
                     });
                }
            };

            dashboardSrv.registerCallback(init);

            init();
    }]);