// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('serviceModalEdit',
        ['$scope', '$modalInstance', '$routeParams', 'services','service', 'servicesManager', 'commonsFact', 'dashboardSrv',
        function($scope, $modalInstance, $routeParams, services, service, servicesManager, commons, dashboardSrv) {

        init = function() {
            // current Workspace
            var ws = $routeParams.wsId;
            // default scope (service)
            $scope.service = {
                "ports": []
            };

            if(service.length == 1) {
                $scope.service = {
                    "name": service[0].name,
                    "description": service[0].description,
                    "owned": service[0].owned,
                    "owner": service[0].owner,
                    "ports": commons.arrayToObject(service[0].ports),
                    "protocol": service[0].protocol,
                    "parent": service[0].parent,
                    "status": service[0].status,
                    "version": service[0].version,
                };
            } else {
                $scope.services_selected = service;
            }
        };

        $scope.ok = function() {
            var ports = [];
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            if($scope.service.ports.length !== 0) {
                $scope.service.ports.forEach(function(port){
                    ports.push(port.key);
                });
                $scope.service.ports = ports.filter(Boolean);
            } else {
                delete $scope.service.ports;
            }
            
            $modalInstance.close($scope.service);
        };

        $scope.newPort = function($event){
            $scope.service.ports.push({key:''});
            $event.preventDefault();
        };

        $scope.call = function(service){
            $scope.service = {
                "name": service.name,
                "description": service.description,
                "owned": service.owned,
                "ports": commons.arrayToObject(service.ports),
                "protocol": service.protocol,
                "status": service.status,
                "version": service.version,
            };
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);