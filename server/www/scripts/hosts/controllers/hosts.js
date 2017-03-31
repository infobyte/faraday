// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsCtrl',
        ['$scope', '$cookies', '$filter', '$location', '$route', '$routeParams', '$uibModal', 'hostsManager', 'workspacesFact', 'commonsFact', 'credential',
        function($scope, $cookies, $filter, $location, $route, $routeParams, $uibModal, hostsManager, workspacesFact, commonsFact, credential) {

        var init = function() {
            $scope.selectall_hosts = false;
            // hosts list
            $scope.hosts = [];
            $scope.totalHosts = 0;
            // current workspace
            $scope.workspace = $routeParams.wsId;

            $scope.sortField = "vulns";
            $scope.sortDirection = "desc";
            $scope.reverse = true;

            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            // paging
            $scope.pageSize = 100;
            $scope.currentPage = 1;
            $scope.newCurrentPage = 1;

            if(!isNaN(parseInt($cookies.pageSize))) $scope.pageSize = parseInt($cookies.pageSize);
            $scope.newPageSize = $scope.pageSize;

            parseSearchQuery();

            loadHosts();
        };

        var parseSearchQuery = function() {
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            $scope.expression = {};

            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                $scope.expression = commonsFact.parseSearchURL($scope.search);
                $scope.searchParams = commonsFact.searchFilterToExpression($scope.expression);
            }
        };

        var loadHosts = function() {
            hostsManager.getHosts(
                $scope.workspace, $scope.currentPage - 1,
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

        var createCredential = function(parent_id, credentialData){
            
            // Add parent id, create credential and save to server.
            credentialData['parent'] = parent_id;
            
            try {
                var credentialObj = new credential(credentialData);
                credentialObj.create($scope.workspace);
                console.log(credentialObj);
            } catch (error) {
                console.log(error);
            }
        };

        $scope.loadIcons = function() {
            $scope.hosts.forEach(function(host) {
                // load icons into object for HTML
                // maybe this part should be directly in the view somehow
                // or, even better, in a CSS file
                var oss = ["windows", "cisco", "router", "osx", "apple","linux", "unix"];
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

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            if (search && params != "" && params != undefined) {
                $scope.expression = commonsFact.parseSearchExpression(params);
            } else {
                $scope.expression = {};
            }

            loadHosts();
        };

        $scope.go = function() {
            if ($scope.newPageSize === undefined)
                $scope.newPageSize = 1;
            $scope.pageSize = $scope.newPageSize;
            $cookies.pageSize = $scope.pageSize;
            $scope.currentPage = 1;
            if ($scope.newCurrentPage <= $scope.pageCount() && $scope.newCurrentPage > 0 &&
                !isNaN(parseInt($scope.newCurrentPage))) {
                $scope.currentPage = $scope.newCurrentPage;
            }
            loadHosts();
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
                    $scope.totalHosts--;
                }, function(message) {
                    console.log(message);
                });
            });
        };

        $scope.delete = function() {
            var selected = [];
            $scope.selectedHosts().forEach(function(select) {
                selected.push(select._id);
            });

            if(selected.length == 0) {
                $uibModal.open({
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
                $uibModal.open({
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

        $scope.insert = function(hostdata, interfaceData, credentialData) {

            var interfaceData = $scope.createInterface(hostdata, interfaceData);
            hostsManager.createHost(hostdata, interfaceData, $scope.workspace).then(function(host) {

                createCredential(hostdata._id, credentialData);
                $scope.hosts.push(host);
                $scope.loadIcons();

            }, function(message) {
                $uibModal.open({
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
            var modal = $uibModal.open({
                templateUrl: 'scripts/hosts/partials/modalNew.html',
                controller: 'hostsModalNew',
                size: 'lg',
                resolve: {}
             });

            modal.result.then(function(data) {
                var hostdata = data[0];
                var interfaceData = data[1];
                var credentialData = data[2];
                $scope.insert(hostdata, interfaceData, credentialData);
            });
        };

        $scope.update = function(host, hostdata, interfaceData) {
            hostsManager.updateHost(host, hostdata, interfaceData, $scope.workspace).then(function() {
                // load icons in case an operating system changed
                $scope.loadIcons();
                loadHosts();
            }, function(message){
                console.log(message);
            });
        };

        $scope.edit = function() {
            if($scope.selectedHosts().length == 1) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/hosts/partials/modalEdit.html',
                    controller: 'hostsModalEdit',
                    size: 'lg',
                    resolve: {
                        host: function(){
                            return $scope.selectedHosts()[0];
                        }
                    }
                 });

                modal.result.then(function(data) {
                    hostdata = data[0];
                    interfaceData = data[1];
                    $scope.update($scope.selectedHosts()[0], hostdata, interfaceData);
                });
            } else {
                $uibModal.open({
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

        $scope.selectedHosts = function() {
            var selected = [];
            $scope.hosts.forEach(function(host) {
                if(host.selected === true) {
                    selected.push(host);
                }
            });
            return selected;
        };

        $scope.checkAll = function() {
            $scope.selectall_hosts = !$scope.selectall_hosts;
            $scope.hosts.forEach(function(host) {
                host.selected = $scope.selectall_hosts;
            });
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

        init();
    }]);
