// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsCtrl', 
                    ['$scope', '$filter', '$route', '$routeParams', '$modal', 'hostsManager', 'workspacesFact', 
                    function($scope, $filter, $route, $routeParams, $modal, hostsManager, workspacesFact) {

        init = function() {
            $scope.selectall = false;
            // hosts list
            $scope.hosts = [];
            // current workspace
            $scope.workspace = $routeParams.wsId;
            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            hostsManager.getHosts($scope.workspace)
                .then(function(hosts) {
                    $scope.hosts = hosts;
                    $scope.loadIcons();
                });

            hostsManager.getAllVulnsCount($scope.workspace)
                .then(function(vulns) {
                    $scope.vulnsCount = {};
                    vulns.forEach(function(vuln) {
                        $scope.vulnsCount[vuln.key] = vuln.value;
                    });
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

        $scope.remove = function(ids) {
            ids.forEach(function(id) {
                hostsManager.deleteHost(id, $scope.workspace).then(function() {
                    var index = -1;
                    for(var i=0; i < $scope.hosts.length; i++) {
                        if($scope.hosts[i]._id === id) {
                            index = i;
                            break;
                        }
                    }
                    $scope.hosts.splice(index, 1);
                }, function(message) {
                    console.log(message);
                });
            });
        };

        $scope.delete = function() {
            var selected = [];

            for(var i=0; i < $scope.hosts.length; i++) {
                var host = $scope.hosts[i];
                if(host.selected) {
                    selected.push(host._id);
                }
            };

            if(selected.length == 0) {
                $modal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return 'No hosts were selected to delete';
                        }
                    }
                })
            } else {
                var message = "A host will be deleted";
                if(selected.length > 1) {
                    message = selected.length  + " hosts will be deleted";
                }
                message = message.concat(" along with all of its children. This operation cannot be undone. Are you sure you want to proceed?");
                $modal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            return message;
                        }
                    }
                }).result.then(function() {
                    $scope.remove(selected);
                }, function() {
                    //dismised, do nothing
                });
            }
        };

        $scope.insert = function(hostdata, interfaceData) {
            var interfaceData = $scope.createInterface(hostdata, interfaceData);
            hostsManager.createHost(hostdata, interfaceData, $scope.workspace).then(function(host) {
                $scope.hosts.push(host);
                $scope.loadIcons();
            }, function(message) {
                $modal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return message;
                        }
                    }
                });
            });
        }

        $scope.new = function() {
            var modal = $modal.open({
                templateUrl: 'scripts/hosts/partials/modalNew.html',
                controller: 'hostsModalNew',
                size: 'lg',
                resolve: {}
             });

            modal.result.then(function(data) {
                hostdata = data[0];
                interfaceData = data[1];
                $scope.insert(hostdata, interfaceData);
            });
        };

        $scope.update = function(host, hostdata, interfaceData) {
            delete host.selected;
            hostsManager.updateHost(host, hostdata, interfaceData, $scope.workspace).then(function() {
                // load icons in case an operating system changed
                $scope.loadIcons();
            }, function(message){
                console.log(message);
            });
        }

        $scope.edit = function() {
            var selected_host = null;

            $scope.hosts.forEach(function(host) {
                if(host.selected) {
                    // if more than one host was selected,
                    // we only use the last one, for now
                    selected_host = host;
                }
            });

            if(selected_host) {
                var modal = $modal.open({
                    templateUrl: 'scripts/hosts/partials/modalEdit.html',
                    controller: 'hostsModalEdit',
                    size: 'lg',
                    resolve: {
                        host: function(){
                            return selected_host;
                        }
                    }
                 });

                modal.result.then(function(data) {
                    hostdata = data[0];
                    interfaceData = data[1];
                    $scope.update(selected_host, hostdata, interfaceData);
                });
            } else {
                $modal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return 'No hosts were selected to edit';
                        }
                    }
                });
            }
        };

        $scope.createInterface = function (hostData, interfaceData){
            if(typeof(hostData.ipv4) == "undefined") hostData.ipv4 = "";
            if(typeof(hostData.ipv6) == "undefined") hostData.ipv6 = "";
            var interfaceData = {
                "_id": CryptoJS.SHA1(hostData.name).toString() + "." + CryptoJS.SHA1("" + "._." + interfaceData.ipv4 + "._." + interfaceData.ipv6).toString(),
                "description": "",
                "hostnames": interfaceData.hostnames,
                "ipv4": {
                    "mask": "0.0.0.0",
                    "gateway": "0.0.0.0",
                    "DNS": [],
                    "address": interfaceData.ipv4
                },
                "ipv6": {
                    "prefix": "00",
                    "gateway": "0000.0000.0000.0000",
                    "DNS": [],
                    "address": interfaceData.ipv6
                },
                "mac": interfaceData.mac,
                "metadata": {
                    "update_time": new Date().getTime(),
                    "update_user": "",
                    "update_action": 0,
                    "creator": "",
                    "create_time": new Date().getTime(),
                    "update_controller_action": "",
                    "owner": "",

                },
                "name": hostData.name,
                "network_segment": "",
                "owned": false,
                "owner": "",
                "parent": CryptoJS.SHA1(hostData.name).toString(),
                "ports": {
                   "filtered": 0,
                   "opened": 0,
                   "closed": 0
                },
                "type": "Interface"
            };
            return interfaceData;
        };

        $scope.checkAll = function() {
            $scope.selectall = !$scope.selectall;

            angular.forEach($filter('filter')($scope.hosts, $scope.query), function(host) {
                host.selected = $scope.selectall;
            });
        };

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
            $scope.reverse = !$scope.reverse;
        }
        
        init();
    }]);
