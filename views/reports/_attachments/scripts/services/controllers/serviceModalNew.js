// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('serviceModalNew',
        ['$scope', '$modalInstance', '$routeParams', 'host', 'servicesManager', 'hostsManager',
        function($scope, $modalInstance, $routeParams, host, servicesManager, hostsManager) {

        init = function(){            
            $scope.service = {
                "name": "",
                "description": "",
                "owned": false,
                "owner": "",
                "ports": [{key: ''}],
                "protocol": "",
                "parent": "",
                "status": "",
                "version": ""
            };
            // current Workspace
            var ws = $routeParams.wsId;

            hostsManager.getInterfaces(ws, host._id).then(function(resp){
                $scope.service.parent = resp[0].value._id;
            });
        };

        $scope.ok = function() {
            var ports = [];
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            $scope.service.ports.forEach(function(port){
                ports.push(port.key);
            });
            $scope.service.metadata = {
                "update_time": timestamp,
                "update_user":  "",
                "update_action": 0,
                "creator": "", 
                "create_time": timestamp,
                "update_controller_action": "UI Web New",
                "owner": ""
            };
            
            $scope.service.ports = ports.filter(Boolean);
            $modalInstance.close($scope.service);
        };

        $scope.newPort = function($event){
            $scope.service.ports.push({key:''});
            $event.preventDefault();
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);