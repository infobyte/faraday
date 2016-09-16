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

            decodeSearchFromURL();

            loadHosts();
        };

        var decodeSearchFromURL = function() {
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            $scope.expression = {};

            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                // search expression for filter
                $scope.expression = $scope.decodeSearch($scope.search);
                // search params for search field, which shouldn't be used for filtering
                $scope.searchParams = $scope.stringSearch($scope.expression);
                // TODO: This sucks man
                $scope.expression = prepareFilter($scope.searchParams);
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

        var prepareFilter = function(searchText) {
            var params = searchText.split(" ");
            var chunks = {};
            var i = -1;

            params.forEach(function(chunk) {
                i = chunk.indexOf(":");
                if (i > 0) {
                    chunks[chunk.slice(0, i)] = chunk.slice(i+1);
                } else {
                    if (!chunks.hasOwnProperty("search")) {
                        chunks.search  = chunk;
                    } else {
                        chunks.search += ' ' + chunk;
                    }
                }
            });

            return chunks;
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            if (search && params != "" && params != undefined) {
                $scope.expression = prepareFilter(params);
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
