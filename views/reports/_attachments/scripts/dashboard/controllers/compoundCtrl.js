// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('compoundCtrl',
        ['$scope', '$routeParams', '$uibModal', 'dashboardSrv',
        function($scope, $routeParams, $uibModal, dashboardSrv) {

            $scope.hosts = [];
            $scope.hostSortField = "name";
            $scope.hostSortReverse = true;
            $scope.workspace;

            $scope.showPagination = 1;
            $scope.currentPage = 0;
            $scope.pageSize = 10;
            $scope.pagination = 10;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getHosts($scope.workspace)
                        .then(function(res) {
                            dashboardSrv.getHostsByServicesCount($scope.workspace)
                                .then(function(servicesCount) {
                                    res.forEach(function(host){
                                        // Maybe this part should be in the view somehow
                                        // or, even better, in CSS file
                                        oss = ["windows", "cisco", "router", "osx", "apple","linux", "unix"];
                                        oss.forEach(function(os) {
                                            if (host.os.toLowerCase().indexOf(os) != -1) {
                                                host.icon = os;
                                                if(os == "unix") {
                                                    host.icon = "linux";
                                                } else if(os == "apple") {
                                                    host.icon = "osx";
                                                }
                                            }
                                        });
                                        host.servicesCount = 0;
                                        servicesCount.forEach(function(count) {
                                            if(count.key == host.id) {
                                                host.servicesCount = count.value;
                                                return
                                            }
                                        });
                                        $scope.hosts.push(host);
                                    });
                                });
                        });
                }
            };

            $scope.hostToggleSort = function(field) {
                $scope.hostToggleSortField(field);
                $scope.hostToggleReverse();
            };

            // toggles column sort field
            $scope.hostToggleSortField = function(field) {
                $scope.hostSortField = field;
            };

            // toggle column sort order
            $scope.hostToggleReverse = function() {
                $scope.hostSortReverse = !$scope.hostSortReverse;
            };

            $scope.numberOfPages = function() {
                $scope.filteredData = $scope.hosts;
                if ($scope.filteredData.length <= 10){
                    $scope.showPagination = 0;
                } else {
                    $scope.showPagination = 1;
                };
                return parseInt($scope.filteredData.length/$scope.pageSize);
            };

            $scope.go = function(page,pagination){
                if(this.go_page < $scope.numberOfPages()+1 && this.go_page > -1){
                    $scope.currentPage = this.go_page;
                }
                $scope.pageSize = this.pagination;
                if(this.go_page > $scope.numberOfPages()){
                    $scope.currentPage = 0;
                }
            };

            $scope.showServices = function(host) {
                if ($scope.workspace != undefined){
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/dashboard/partials/modal-services-by-host.html',
                        controller: 'summarizedCtrlServicesModal',
                        size: 'lg',
                        resolve: {
                            host: function() {
                                return host
                            },
                            workspace: function() {
                                return $scope.workspace;
                            }
                        }
                     });
                }
            };

            $scope.showHosts = function(srv_name) {
                if ($scope.workspace != undefined){
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/dashboard/partials/modal-hosts-by-service.html',
                        controller: 'summarizedCtrlHostsModal',
                        size: 'lg',
                        resolve: {
                            srv_name: function(){
                                return srv_name
                            },
                            workspace: function(){
                                return $scope.workspace;
                            }
                        }
                     });
                }
            };

            init();
    }]);