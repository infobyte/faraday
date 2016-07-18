// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('serviceModalEdit',
        ['$scope', '$modalInstance', '$routeParams', 'services','service', 'servicesManager', 'commonsFact',
        function($scope, $modalInstance, $routeParams, services, service, servicesManager, commons) {

        init = function() {
            // current Workspace
            var ws = $routeParams.wsId;

            if(service.length == 1) {
                $scope.service = {
                    "name": service[0].name,
                    "description": service[0].description,
                    "owned": service[0].owned,
                    "owner": service[0].owner,
                    "ports": service[0].ports,
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
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            $modalInstance.close($scope.service);
        };

        $scope.call = function(service) {
            $scope.service = {
                "name": service.name,
                "description": service.description,
                "owned": service.owned,
                "ports": service.ports,
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
