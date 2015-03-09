angular.module('faradayApp')
    .controller('summarizedCtrl', 
        ['$scope', '$route', '$routeParams', '$modal', 'dashboardSrv',
        function($scope, $route, $routeParams, $modal, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.servicesCount = [];
            $scope.objectsCount = [];
            $scope.vulnsCount = [];
            $scope.commands = [];
            $scope.hosts = [];
            $scope.showPagination = 1;
            $scope.currentPage = 0;
            $scope.pageSize = 10;
            $scope.pagination = 10;

            // cmd table sorting
            $scope.cmdSortField = 'date';
            $scope.cmdSortReverse = true;
            // toggles sort field and order
            $scope.cmdToggleSort = function(field) {
                $scope.cmdToggleSortField(field);
                $scope.cmdToggleReverse();
            };

            // toggles column sort field
            $scope.cmdToggleSortField = function(field) {
                $scope.cmdSortField = field;
            };

            // toggle column sort order
            $scope.cmdToggleReverse = function() {
                $scope.cmdSortReverse = !$scope.cmdSortReverse;
            }

            // host table sorting
            $scope.hostSortField = 'name';
            $scope.hostSortReverse = true;
            // toggles sort field and order
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
            }

            if (workspace != undefined){
                $scope.workspace = workspace;
                dashboardSrv.getServicesCount(workspace).then(function(res){
                    res.sort(function(a, b){
                        return b.value - a.value;
                    });
                    $scope.servicesCount = res;

                });
                dashboardSrv.getObjectsCount(workspace).then(function(res){
                    for(var i = res.length - 1; i >= 0; i--) {
                        if(res[i].key === "interfaces") {
                           res.splice(i, 1);
                        }
                    }
                    $scope.objectsCount = res;
                });
                dashboardSrv.getVulnerabilitiesCount(workspace).then(function(res){
                    if (res.length > 0) {
                        var tmp = [
                            {"key": "critical", "value": 0},
                            {"key": "high", "value": 0},
                            {"key": "med", "value": 0},
                            {"key": "low", "value": 0},
                            {"key": "info", "value": 0},
                            {"key": "unclassified", "value": 0}
                        ];

                        function accumulate(_array, key, value){
                            _array.forEach(function(obj){
                                if (obj.key == key){
                                    obj.value += value;
                                }
                            });
                        }

                        res.forEach(function(tvuln){
                            if (tvuln.key == 1 || tvuln.key == "info"){
                                accumulate(tmp, "info", tvuln.value);
                            } else if (tvuln.key == 2 || tvuln.key == "low") {
                                accumulate(tmp, "low", tvuln.value);
                            } else if (tvuln.key == 3 || tvuln.key == "med") {
                                accumulate(tmp, "med", tvuln.value);
                            } else if (tvuln.key == 4 || tvuln.key == "high") {
                                accumulate(tmp, "high", tvuln.value);
                            } else if (tvuln.key == 5 || tvuln.key == "critical") {
                                accumulate(tmp, "critical", tvuln.value);
                            }
                        });
                        $scope.vulnsCount = tmp;
                    }
                });
                dashboardSrv.getCommands(workspace).then(function(res){
                    res.forEach(function(cmd){
                        cmd.user = cmd.user || "unknown";
                        cmd.hostname = cmd.hostname || "unknown";
                        cmd.ip = cmd.ip || "0.0.0.0";
                        if(cmd.duration == "0" || cmd.duration == "") {
                            cmd.duration = "In progress";
                        } else if (cmd.duration != undefined) {
                            cmd.duration = cmd.duration.toFixed(2) + "s";
                        } else {
                            cmd.duration = "undefined";
                        }
                        var d = new Date(0);
                        d.setUTCSeconds(cmd.startdate);
                        var mins = (d.getMinutes()<10?'0':'') + d.getMinutes();
                        d = d.getDate() + "/" + (d.getMonth() + 1) + "/" + d.getFullYear() + " - " + d.getHours() + ":" + mins;
                        cmd.date = d;
                    });
                    $scope.commands = res;
                });
                dashboardSrv.getHosts(workspace).then(function(res){
                    res.forEach(function(host){
                        // Maybe this part should be in the view somehow
                        // or, even better, in CSS file
                        oss = ["windows", "cisco", "router", "osx", "apple","linux", "unix"];
                        oss.forEach(function(os){
                            if (host.os.toLowerCase().indexOf(os) != -1) {
                                host.icon = os;
                                if (os == "unix") {
                                    host.icon = "linux";
                                }else if (os == "apple") {
                                    host.icon = "osx";
                                }
                            }
                        });

                        host.servicesCount = 0;
                        dashboardSrv.getHostsByServicesCount(workspace, host.id).then(function(res){
                            if (res.length == 1) {
                                if (res[0].key == host.id){
                                    host.servicesCount = res[0].value;
                                }
                            }
                            $scope.hosts.push(host);
                        });
                    });
                });
            }

            $scope.numberOfPages = function() {
                $scope.filteredData = $scope.hosts;
                if ($scope.filteredData.length <= 10){
                    $scope.showPagination = 0;
                } else {
                    $scope.showPagination = 1;
                };
                return parseInt($scope.filteredData.length/$scope.pageSize);
            }

            $scope.go = function(page,pagination){
                if(this.go_page < $scope.numberOfPages()+1 && this.go_page > -1){
                    $scope.currentPage = this.go_page;
                }
                $scope.pageSize = this.pagination;
                if(this.go_page > $scope.numberOfPages()){
                    $scope.currentPage = 0;
                }
            }

            $scope.showServices = function(host_id) {
                if ($scope.workspace != undefined){
                    var modal = $modal.open({
                        templateUrl: 'scripts/dashboard/partials/modal-services-by-host.html',
                        controller: 'summarizedCtrlServicesModal',
                        size: 'lg',
                        resolve: {
                            host_id: function(){
                                return host_id
                            },
                            workspace: function(){
                                return $scope.workspace;
                            }
                        }
                     });
                }
            }

            $scope.showHosts = function(srv_name) {
                if ($scope.workspace != undefined){
                    var modal = $modal.open({
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
            }
    }]);

angular.module('faradayApp')
    .controller('summarizedCtrlServicesModal', 
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace', 'host_id',
        function($scope, $modalInstance, dashboardSrv, workspace, host_id) {

            $scope.sortField = 'port';
            $scope.sortReverse = false;
            
            // toggles sort field and order
            $scope.toggleSort = function(field) {
                $scope.toggleSortField(field);
                $scope.toggleReverse();
            };

            // toggles column sort field
            $scope.toggleSortField = function(field) {
                $scope.sortField = field;
            };

            // toggle column sort order
            $scope.toggleReverse = function() {
                $scope.sortReverse = !$scope.sortReverse;
            }

            dashboardSrv.getServicesByHost(workspace, host_id).then(function(services){
                dashboardSrv.getName(workspace, host_id).then(function(name){
                    $scope.name = name;
                    $scope.services = services;
                })
            });

            $scope.ok = function(){
                $modalInstance.close();
            }

    }]);

angular.module('faradayApp')
    .controller('summarizedCtrlHostsModal', 
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace', 'srv_name',
        function($scope, $modalInstance, dashboardSrv, workspace, srv_name) {

            $scope.sortField = 'name';
            $scope.sortReverse = false;
            $scope.clipText = "Copy to Clipboard";
            
            // toggles sort field and order
            $scope.toggleSort = function(field) {
                $scope.toggleSortField(field);
                $scope.toggleReverse();
            };

            // toggles column sort field
            $scope.toggleSortField = function(field) {
                $scope.sortField = field;
            };

            // toggle column sort order
            $scope.toggleReverse = function() {
                $scope.sortReverse = !$scope.sortReverse;
            }

            dashboardSrv.getHostsByServicesName(workspace, srv_name).then(function(hosts){
                $scope.name = srv_name;
                $scope.hosts = hosts;
                $scope.clip = "";
                $scope.hosts.forEach(function(h){
                    $scope.clip += h.name + "\n";
                });
            });

            $scope.messageCopied = function(){
                $scope.clipText = "Copied!";
            }

            $scope.ok = function(){
                $modalInstance.close();
            }

    }]);