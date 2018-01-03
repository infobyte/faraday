// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('compoundCtrl',
        ['$scope', '$location', '$route', '$routeParams', '$uibModal', 'hostsManager', 'workspacesFact', 'dashboardSrv',
        function($scope, $location, $route, $routeParams, $uibModal, hostsManager, workspacesFact, dashboardSrv) {

        init = function() {
            // hosts list
            $scope.hosts = [];
            $scope.totalHosts = 0;
            // current workspace
            $scope.workspace = $routeParams.wsId;

            $scope.sortField = "services";
            $scope.sortDirection = "desc";
            $scope.reverse = true;

            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            // paging
            $scope.pageSize = 10;
            $scope.currentPage = 1;
            $scope.newCurrentPage = 1;
            $scope.newPageSize = $scope.pageSize;

            loadHosts();
        };

        var loadHosts = function() {
            hostsManager.getHosts(
                $scope.workspace, $scope.currentPage,
                $scope.pageSize, $scope.expression,
                $scope.sortField, $scope.sortDirection)
                .then(function(batch) {
                    $scope.hosts = batch.hosts;
                    $scope.totalHosts = batch.total;
                    $scope.loadedVulns = true;
                    $scope.loadIcons();
                })
                .catch(function(e) {
                    console.log(e);
                });
        };

        $scope.loadIcons = function() {
            $scope.hosts.forEach(function(host) {
                // load icons into object for HTML
                // maybe this part should be directly in the view somehow
                // or, even better, in a CSS file
                oss = ["windows", "cisco", "router", "osx", "apple","linux", "unix"];
                oss.forEach(function(os){
                    if(host.os.toLowerCase().indexOf(os) != -1) {
                        host.icon = os;
                        if(os == "unix") {
                            host.icon = "linux";
                        } else if(os == "apple") {
                            host.icon = "osx";
                        }
                    }
                });
            });
        };

        $scope.go = function() {
            $scope.pageSize = $scope.newPageSize;
            $scope.currentPage = 1;
            if ($scope.newCurrentPage <= $scope.pageCount() && $scope.newCurrentPage > 0 &&
                !isNaN(parseInt($scope.newCurrentPage))) {
                $scope.currentPage = $scope.newCurrentPage;
            }
            loadHosts();
        };

        // toggles sort field and order
        $scope.toggleSort = function(field) {
            if ($scope.sortField != field) {
                $scope.sortDirection = "desc";
            } else {
                $scope.toggleReverse();
            }
            $scope.sortField = field;
            loadHosts();
        };

        // toggle column sort order
        $scope.toggleReverse = function() {
            if ($scope.sortDirection == "asc") {
                $scope.sortDirection = "desc";
            } else {
                $scope.sortDirection = "asc";
            }
        }

        // paging
        $scope.prevPage = function() {
            $scope.currentPage -= 1;
            loadHosts();
        };

        $scope.prevPageDisabled = function() {
            return $scope.currentPage <= 1;
        };

        $scope.nextPage = function() {
            $scope.currentPage += 1;
            loadHosts();
        };

        $scope.nextPageDisabled = function() {
            return $scope.currentPage >= $scope.pageCount();
        };

        $scope.pageCount = function() {
            return Math.ceil($scope.totalHosts / $scope.pageSize);
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
                        },
                        osint: function() {
                            return $scope.osint;
                        }
                    }
                 });
            }
        };

        dashboardSrv.registerCallback(loadHosts);

        init();
    }]);
