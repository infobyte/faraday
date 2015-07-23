// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostCtrl',
        ['$scope', '$filter', '$route', '$routeParams', '$modal', 'hostsManager', 'workspacesFact', 'dashboardSrv', 'servicesManager',
        function($scope, $filter, $route, $routeParams, $modal, hostsManager, workspacesFact, dashboardSrv, servicesManager) {


	    init = function() {
	    	$scope.selectall = false;
            // current workspace
            $scope.workspace = $routeParams.wsId;
            //ID of current host
            var hostId = $routeParams.hidId;
            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });
            // current host
            hostsManager.getHost(hostId, $scope.workspace).then(function(host){
            	$scope.host = host;
            });
            // services by host
            $scope.services = [];
            dashboardSrv.getServicesByHost($scope.workspace, hostId).then(function(services){
            	services.forEach(function(service){
                    servicesManager.getService(service.id, $scope.workspace, true).then(function(s){
                        $scope.services.push(s);
                    });
                });
            });
	    };

        $scope.new = function() {
            var modal = $modal.open({
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
        };

        $scope.update = function(services, data) {
            services.forEach(function(service){            	
                delete service.selected;
	            servicesManager.updateService(service, data, $scope.workspace).then(function(s) {
	            }, function(message){
	                console.log(message);
	            });
            });
        };

        $scope.edit = function() {
            var selected_service = [];

            $scope.services.forEach(function(service) {
                if(service.selected) {
                    // if more than one service was selected,
                    // we only use the last one, for now
                    selected_service.push(service);
                }
            });

            if(selected_service.length > 0) {
                var modal = $modal.open({
                    templateUrl: 'scripts/services/partials/modalEdit.html',
                    controller: 'serviceModalEdit',
                    size: 'lg',
                    resolve: {
                        service: function() {
                            return selected_service;
                        },
	                    services: function() {
	                        return $scope.services;
	                    }
                    }
                 });

                modal.result.then(function(data) {
                    $scope.update(selected_service, data);
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

        $scope.delete = function() {
            var selected = [];
            $scope.services.forEach(function(service){
            	if(service.selected){
            		selected.push(service._id);
            	}
            });

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
