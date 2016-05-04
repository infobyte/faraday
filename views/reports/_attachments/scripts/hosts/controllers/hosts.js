// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsCtrl',
        ['$scope', '$cookies', '$filter', '$location', '$route', '$routeParams', '$uibModal', 'hostsManager', 'workspacesFact',
        function($scope, $cookies, $filter, $location, $route, $routeParams, $uibModal, hostsManager, workspacesFact) {

        init = function() {
            $scope.selectall_hosts = false;
            // hosts list
            $scope.hosts = [];
            // current workspace
            $scope.workspace = $routeParams.wsId;

            $scope.sortField = "name";

            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            hostsManager.getHosts($scope.workspace)
                .then(function(hosts) {
                    $scope.hosts = hosts;
                    $scope.loadedVulns = true;
                    $scope.loadIcons();

                    hostsManager.getAllServicesCount($scope.workspace)
                        .then(function(servicesCount) {
                            $scope.servicesCount = servicesCount;
                            $scope.hosts.forEach(function(host) {
                                host.services = servicesCount[host._id];
                            });
                        });

                    hostsManager.getAllVulnsCount($scope.workspace)
                        .then(function(vulns) {
                            $scope.vulnsCount = {};
                            vulns.forEach(function(vuln) {
                                var parts = vuln.key.split("."),
                                parent = parts[0];

                                if(parts.length > 1) $scope.vulnsCount[vuln.key] = vuln.value;
                                if($scope.vulnsCount[parent] == undefined) $scope.vulnsCount[parent] = 0;
                                $scope.vulnsCount[parent] += vuln.value;
                            });
                        })
                        .catch(function(e) {
                            console.log(e);
                        });
                });

            $scope.pageSize = 10;
            $scope.currentPage = 0;
            $scope.newCurrentPage = 0;

            if(!isNaN(parseInt($cookies.pageSize))) $scope.pageSize = parseInt($cookies.pageSize);
            $scope.newPageSize = $scope.pageSize;

            // current search
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            $scope.expression = {};
            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                // search expression for filter
                $scope.expression = $scope.decodeSearch($scope.search);
                // search params for search field, which shouldn't be used for filtering
                $scope.searchParams = $scope.stringSearch($scope.expression);
            }
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

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            var url = "/hosts/ws/" + $routeParams.wsId;

            if(search && params != "" && params != undefined) {
                url += "/search/" + $scope.encodeSearch(params);
            }

            $location.path(url);
        };

        $scope.go = function() {
            $scope.pageSize = $scope.newPageSize;
            $cookies.pageSize = $scope.pageSize;
            $scope.currentPage = 0;
            if($scope.newCurrentPage <= parseInt($scope.hosts.length/$scope.pageSize)
                    && $scope.newCurrentPage > -1 && !isNaN(parseInt($scope.newCurrentPage))) {
                $scope.currentPage = $scope.newCurrentPage;
            }
        };

        // encodes search string in order to send it through URL
        $scope.encodeSearch = function(search) {
            var i = -1,
            encode = "",
            params = search.split(" "),
            chunks = {};

            params.forEach(function(chunk) {
                i = chunk.indexOf(":");
                if(i > 0) {
                    chunks[chunk.slice(0, i)] = chunk.slice(i+1);
                } else {
                    if(!chunks.hasOwnProperty("free")) {
                        chunks.free = "";
                    }
                    chunks.free += " ".concat(chunk);
                }
            });

            if(chunks.hasOwnProperty("free")) {
                chunks.free = chunks.free.slice(1);
            }

            for(var prop in chunks) {
                if(chunks.hasOwnProperty(prop)) {
                    if(chunks.prop != "") {
                        encode += "&" + encodeURIComponent(prop) + "=" + encodeURIComponent(chunks[prop]);
                    }
                }
            }
            return encode.slice(1);
        };

        // decodes search parameters to object in order to use in filter
        $scope.decodeSearch = function(search) {
            var i = -1,
            decode = {},
            params = search.split("&");

            params.forEach(function(param) {
                i = param.indexOf("=");
                decode[decodeURIComponent(param.slice(0,i))] = decodeURIComponent(param.slice(i+1));
            });

            if(decode.hasOwnProperty("free")) {
                decode['$'] = decode.free;
                delete decode.free;
            }

            return decode;
        };

        // converts current search object to string to be displayed in search field
        $scope.stringSearch = function(obj) {
            var search = "";

            for(var prop in obj) {
                if(obj.hasOwnProperty(prop)) {
                    if(search != "") {
                        search += " ";
                    }
                    if(prop == "$") {
                        search += obj[prop];
                    } else {
                        search += prop + ":" + obj[prop];
                    }
                }
            }

            return search;
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
            $scope.selectedHosts().forEach(function(select) {
                selected.push(select._id);
            });

            if(selected.length == 0) {
                $uibModal.open(config = {
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
                $uibModal.open(config = {
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
                $uibModal.open(config = {
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
                $uibModal.open(config = {
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
            selected = [];

            tmp_hosts = filter($scope.hosts);
            tmp_hosts.forEach(function(host) {
                if(host.selected === true) {
                    selected.push(host);
                }
            });
            return selected;
        };

        $scope.checkAll = function() {
            $scope.selectall_hosts = !$scope.selectall_hosts;

            tmp_hosts = filter($scope.hosts);
            tmp_hosts.forEach(function(host) {
                host.selected = $scope.selectall_hosts;
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

        filter = function(data) {
            var tmp_data = $filter('orderBy')(data, $scope.sortField, $scope.reverse);
            tmp_data = $filter('filter')(tmp_data, $scope.expression);
            tmp_data = tmp_data.splice($scope.pageSize * $scope.currentPage, $scope.pageSize);

            return tmp_data;
        };

        init();
    }]);
