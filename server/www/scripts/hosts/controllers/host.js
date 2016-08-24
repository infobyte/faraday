// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostCtrl',
        ['$scope', '$cookies', '$filter', '$location', '$route', '$routeParams', '$uibModal', '$q',
            'hostsManager', 'workspacesFact', 'dashboardSrv', 'servicesManager',
            function($scope, $cookies, $filter, $location, $route, $routeParams, $uibModal, $q,
            hostsManager, workspacesFact, dashboardSrv, servicesManager) {

	    init = function() {
	    	$scope.selectall_service = false;
            // current workspace
            $scope.workspace = $routeParams.wsId;
            //ID of current host
            var hostId = $routeParams.hidId;

            $scope.services = [];
            $scope.sortField = "name";
            $scope.reverse = false;

            $scope.loadedServices = false;

            // load all workspaces
            workspacesFact.list()
                .then(function(wss) {
                    $scope.workspaces = wss;
                });

            // current host
            hostsManager.getHost(hostId, $scope.workspace)
                .then(function(host) {
                	$scope.host = host;
                });

            // services by host
            dashboardSrv.getServicesByHost($scope.workspace, hostId)
                .then(function(services) {
                    var pss = [];

                    services.forEach(function(service) {
                        pss.push(servicesManager.getService(service.id, $scope.workspace, true));
                    });

                    return $q.all(pss);
                })
                .then(function(services) {
                    $scope.services = services;

                    $scope.services.forEach(function(service) {
                        service.uri = encodeURIComponent(encodeURIComponent("(" + service.ports + "/" + service.protocol + ") " + service.name));
                    });

                    $scope.loadedServices = true;

                    return hostsManager.getAllVulnsCount($scope.workspace);
                })
                .then(function(vulns) {
                    var vulnsCount = {};
                    vulns.forEach(function(vuln) {
                        vulnsCount[vuln.key] = vuln.value;
                    });
                    $scope.services.forEach(function(service) {
                        service.vulns = vulnsCount[service._id] || 0;
                    });
                })
                .catch(function(e) {
                    console.log(e);
                });

            $scope.pageSize = 10;
            $scope.currentPage = 1;
            $scope.newCurrentPage = 1;

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

        $scope.selectedServices = function() {
            selected = [];

            tmp_services = filter($scope.services);
            tmp_services.forEach(function(service) {
                if(service.selected === true) {
                    selected.push(service);
                }
            });
            return selected;
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            var url = "/host/ws/" + $routeParams.wsId + "/hid/" + $routeParams.hidId;

            if(search && params != "" && params != undefined) {
                url += "/search/" + $scope.encodeSearch(params);
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

        $scope.new = function() {
            var modal = $uibModal.open({
                templateUrl: 'scripts/services/partials/modalNew.html',
                controller: 'serviceModalNew',
                size: 'lg',
                resolve: {
                    host: function() {
                        return $scope.host;
                    }
                }
             });

            modal.result.then(function(data) {
                $scope.insert(data);
            });
        };

        $scope.insert = function(service) {
            servicesManager.createService(service, $scope.workspace).then(function(service) {
                $scope.services.push(service);
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
        };

        $scope.update = function(services, data) {
            services.forEach(function(service) {
	            servicesManager.updateService(service, data, $scope.workspace).then(function(s) {
	            }, function(message) {
	                console.log(message);
	            });
            });
        };

        $scope.edit = function() {
            if($scope.selectedServices().length > 0) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/services/partials/modalEdit.html',
                    controller: 'serviceModalEdit',
                    size: 'lg',
                    resolve: {
                        service: function() {
                            return $scope.selectedServices();
                        },
	                    services: function() {
	                        return $scope.services;
	                    }
                    }
                 });

                modal.result.then(function(data) {
                    $scope.update($scope.selectedServices(), data);
                });
            } else {
                $uibModal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return 'No services were selected to edit';
                        }
                    }
                });
            }
        };

        $scope.delete = function() {
            var selected = [];
            $scope.selectedServices().forEach(function(service){
            	if(service.selected){
            		selected.push(service._id);
            	}
            });

            if(selected.length == 0) {
                $uibModal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return 'No services were selected to delete';
                        }
                    }
                })
            } else {
                var message = "A service will be deleted";
                if(selected.length > 1) {
                    message = selected.length  + " services will be deleted";
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

        $scope.remove = function(ids) {
            ids.forEach(function(id) {
                servicesManager.deleteServices(id, $scope.workspace).then(function() {
                    var index = -1;
                    for(var i=0; i < $scope.services.length; i++) {
                        if($scope.services[i]._id === id) {
                            index = i;
                            break;
                        }
                    }
                    $scope.services.splice(index, 1);
                }, function(message) {
                    console.log(message);
                });
            });
        };

        $scope.checkAllServices = function() {
            $scope.selectall_service = !$scope.selectall_service;

            tmp_services = filter($scope.services);
            tmp_services.forEach(function(service) {
                service.selected = $scope.selectall_service;
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

        // paging

        $scope.prevPage = function() {
            $scope.currentPage -= 1;
        };

        $scope.prevPageDisabled = function() {
            return $scope.currentPage <= 1;
        };

        $scope.nextPage = function() {
            $scope.currentPage += 1;
        };

        $scope.nextPageDisabled = function() {
            return $scope.currentPage >= $scope.pageCount();
        };

        $scope.pageCount = function() {
            return Math.ceil($scope.services.length / $scope.pageSize);
        };

	    init();
    }]);
