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
            $scope.columns = {
                "id": false,
                "ip": true,
                "description": false,
                "hostnames": false,
                "services": false,
                "mac": false,
                "vendor": false,
                "service_count": true,
                "vuln_count": true,
                "credential_count": true,
                "os": true,
                "owned": true,
                "create_time": true,
                "last_modified": true,
            }
            if($cookies.get('HColumns')) {
                preferences = JSON.parse($cookies.get('HColumns'))
                angular.extend($scope.columns, preferences);
            }
            // current workspace
            $scope.workspace = $routeParams.wsId;

            // load current workspace data
            workspacesFact.get($scope.workspace).then(function(response) {
                $scope.workspaceData = response;
            });

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
                $scope.workspace, $scope.currentPage,
                $scope.pageSize, $scope.expression,
                $scope.sortField, $scope.sortDirection)
                .then(function(batch) {
                    $scope.hosts = batch.hosts;
                    $scope.totalHosts = batch.total;
                    $scope.loadedVulns = true;
                    $scope.loadIcons();
                    $scope.loadMac();
                })
                .catch(function(e) {
                    console.log(e);
                });
        };

        var createCredential = function(credentialData, parent_id){

            // Add parent id, create credential and save to server.
            try {
                var credentialObj = new credential(credentialData, parent_id);
                credentialObj.create($scope.workspace);
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

       $scope.loadMac = function() {
           $scope.hosts.forEach(function(host) {
               var mac_vendor = [""];
               mac_vendor.forEach(function(mac){
                if(host.mac == "00:00:00:00:00:00" || host.mac == ""){
                    host.mac = "-";
                    host.mac_vendor = "-";
                } else {
                    host.mac_vendor = oui(host.mac);
                }
               });
           });
       };
        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            // TODO: It would be nice to find a way for changing
            // the url without reloading the controller
            var url = "/hosts/ws/" + $routeParams.wsId;

            if(search && params != "" && params != undefined) {
                var filter = commonsFact.parseSearchExpression(params);
                var URLParams = commonsFact.searchFilterToURLParams(filter);
                url += "/search/" + URLParams;
            }

            $location.path(url);
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

        $scope.insert = function(hostdata, credentialData) {

            hostsManager.createHost(hostdata, $scope.workspace).then(function(host) {
                if(credentialData.name && credentialData.username && credentialData.password){
                    createCredential(credentialData, hostdata._id);
                    host.credentials = 1;
                }
                $scope.hosts.push(host);
                $scope.loadIcons();
                $scope.loadMac();

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
            $location.path('/host/ws/' + $scope.workspace + '/new');
        };

        $scope.update = function(host, hostdata) {
            hostsManager.updateHost(host, hostdata, $scope.workspace).then(function() {
                // load icons in case an operating system changed
                $scope.loadIcons();
                $scope.loadMac();
                loadHosts();
            }, function(message){
                console.log(message);
            });
        };

        $scope.edit = function() {
            if($scope.selectedHosts().length == 1) {
                var hostId = $scope.selectedHosts()[0]._id;
                $location.path('/host/ws/' + $scope.workspace + '/hid/' + hostId + '/edit');
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

        $scope.hasDisabledFields = function(){
            return Object.values($scope.columns).some(function(show){
                return !show
            });
        };

        $scope.toggleShow = function(column) {
            $scope.columns[column] = !$scope.columns[column];
            $cookies.put('HColumns', JSON.stringify($scope.columns));
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
