// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('summarizedCtrl', 
        ['$scope', '$route', '$routeParams', '$modal', 'dashboardSrv', 'vulnsManager',
        function($scope, $route, $routeParams, $modal, dashboardSrv, vulnsManager) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.servicesCount = [];
            $scope.objectsCount = [];
            $scope.commands = [];
            $scope.hosts = [];
            $scope.showPagination = 1;
            $scope.currentPage = 0;
            $scope.pageSize = 10;
            $scope.pagination = 10;
            $scope.vulns;

            // graphicsBarCtrl data
            $scope.topServices; // previously known as treemapData
            $scope.topHosts; // previously known as barData
            $scope.vulnsCount;
            $scope.vulnsCountClass; // classified vulns count 

            // vulnsByPrice
            $scope.workspaceWorth;
            $scope.vulnPrices = dashboardSrv.vulnPrices;

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

            // vuln table sorting
            $scope.vulnSortField = 'metadata.create_time';
            $scope.vulnSortReverse = true;
            // toggles sort field and order
            $scope.vulnToggleSort = function(field) {
                $scope.vulnToggleSortField(field);
                $scope.vulnToggleReverse();
            };

            // toggles column sort field
            $scope.vulnToggleSortField = function(field) {
                $scope.vulnSortField = field;
            };

            // toggle column sort order
            $scope.vulnToggleReverse = function() {
                $scope.vulnSortReverse = !$scope.vulnSortReverse;
            };

            if(workspace != undefined) {
                $scope.workspace = workspace;

                dashboardSrv.getServicesCount(workspace).then(function(res) {
                    res.sort(function(a, b) {
                        return b.value - a.value;
                    });

                    $scope.servicesCount = res;

                    if(res.length > 4) {
                        var colors = ["#FA5882", "#FF0040", "#B40431", "#610B21", "#2A0A1B"];
                        var tmp = [];
                        res.slice(0, 5).forEach(function(srv) {
                            srv.color = colors.shift();
                            tmp.push(srv);
                        });
                        $scope.topServices = {"children": tmp};
                    }
                });

                dashboardSrv.getObjectsCount(workspace).then(function(res){
                    for(var i = res.length - 1; i >= 0; i--) {
                        if(res[i].key === "interfaces") {
                           res.splice(i, 1);
                        }
                    }
                    $scope.objectsCount = res;
                });

                dashboardSrv.getVulnerabilitiesCount(workspace).then(function(res) {
                    if(res.length > 0) {
                        var tmp = [
                            {"key": "critical", "value": 0, "color": "#8B00FF", "amount": 0},
                            {"key": "high", "value": 0, "color": "#DF3936", "amount": 0},
                            {"key": "med", "value": 0, "color": "#DFBF35", "amount": 0},
                            {"key": "low", "value": 0, "color": "#A1CE31", "amount": 0},
                            {"key": "info", "value": 0, "color": "#428BCA", "amount": 0},
                            {"key": "unclassified", "value": 0, "color": "#999999", "amount": 0}
                        ];

                        res.forEach(function(tvuln) {
                            if(tvuln.key == 1 || tvuln.key == "info") {
                                dashboardSrv.accumulate(tmp, "info", tvuln.value, "value");
                            } else if (tvuln.key == 2 || tvuln.key == "low") {
                                dashboardSrv.accumulate(tmp, "low", tvuln.value, "value");
                            } else if (tvuln.key == 3 || tvuln.key == "med") {
                                dashboardSrv.accumulate(tmp, "med", tvuln.value, "value");
                            } else if (tvuln.key == 4 || tvuln.key == "high") {
                                dashboardSrv.accumulate(tmp, "high", tvuln.value, "value");
                            } else if (tvuln.key == 5 || tvuln.key == "critical") {
                                dashboardSrv.accumulate(tmp, "critical", tvuln.value, "value");
                            } else if (tvuln.key == 6 || tvuln.key == "unclassified") {
                                dashboardSrv.accumulate(tmp, "unclassified", tvuln.value, "value");
                            }
                        });

                        // used to create colored boxes for vulns
                        $scope.vulnsCount = tmp;

                        // used to create workspace's worth
                        $scope.generateVulnPrices($scope.vulnsCount, $scope.vulnPrices);
                        $scope.workspaceWorth = $scope.sumProperty($scope.vulnsCount, "amount");

                        // used to create pie chart for vulns
                        $scope.vulnsCountClass = {"children": angular.copy(tmp)};
                        for(var i = 0; i < $scope.vulnsCountClass.children.length; i++) {
                            if($scope.vulnsCountClass.children[i].key == "unclassified") {
                                $scope.vulnsCountClass.children.splice(i, 1);
                                break;
                            }
                        };

                        $scope.$watch('vulnPrices', function(ps) {
                            if($scope.vulnsCount != undefined) {
                                $scope.generateVulnPrices($scope.vulnsCount, $scope.vulnPrices);
                                $scope.workspaceWorth = $scope.sumProperty($scope.vulnsCount, "amount");
                            }
                        }, true);
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
                        }
                        cmd.date = cmd.startdate * 1000;
                    });
                    $scope.commands = res;
                });

                dashboardSrv.getHosts(workspace).then(function(res){
                    dashboardSrv.getHostsByServicesCount(workspace).then(function(servicesCount) {
                        res.forEach(function(host){
                            // Maybe this part should be in the view somehow
                            // or, even better, in CSS file
                            oss = ["windows", "cisco", "router", "osx", "apple","linux", "unix"];
                            oss.forEach(function(os) {
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
                            servicesCount.forEach(function(count){
                                if (count.key == host.id) {
                                    host.servicesCount = count.value;
                                    return
                                }
                            });
                            // load data for Top Hosts
                            if(servicesCount.length > 2) {
                                servicesCount.sort(function(a, b) {
                                    return b.value-a.value;
                                });
                                var colors = ["rgb(57, 59, 121)","rgb(82, 84, 163)","rgb(107, 110, 207)"];
                                var tmp = [];
                                servicesCount.slice(0, 3).forEach(function(srv) {
                                    srv.color = colors.shift();
                                    tmp.push(srv);
                                });
                                $scope.topHosts = tmp;
                            }
                            $scope.hosts.push(host);
                        });
                    });
                });

                vulnsManager.getVulns(workspace).then(function(vulns) {
                    $scope.vulns = vulns;
                });
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
            };

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
            };

            $scope.treemap = function(data) {
                if(data !== undefined && data != {}) {
                    var modal = $modal.open({
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

            $scope.sumProperty = function(data, prop) {
                var total = 0;

                for(var d in data) {
                    if(data.hasOwnProperty(d)) {
                        if(data[d][prop] !== undefined) total += parseInt(data[d][prop]);
                    }
                }

                return total;
            };

            $scope.generateVulnPrices = function(vulns, prices) {
                vulns.forEach(function(vuln) {
                    vuln.amount = vuln.value * prices[vuln.key];
                });
            };
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
