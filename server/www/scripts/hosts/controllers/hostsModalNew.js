// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsModalNew',
        ['$scope', '$modalInstance', 'hostsManager',
        function($scope, $modalInstance, hostsManager) {
        
        $scope.hostdata = {
            "name": "",
            "description": "",
            "default_gateway": "None",
            "os": "",
            "owned": false,
            "owner": "",
        };

        $scope.credentialData = {
            'name': '',
            'username': '',
            'password': ''
        };

        $scope.ok = function() {
            var hostnames = [];
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            if($scope.hostdata.parent == undefined) $scope.hostdata.parent = null;

            $scope.interfaceData.hostnames.forEach(function(hname){
                hostnames.push(hname.hostname);
            });

            $scope.hostdata.hostnames = hostnames.filter(Boolean);
            $scope.hostdata.interfaceName = $scope.hostdata.name;
            $scope.hostdata.metadata = {
                "update_time": timestamp,
                "update_user":  "",
                "update_action": 0,
                "creator": "", 
                "create_time": timestamp,
                "update_controller_action": "UI Web New",
                "owner": ""
            };

            $modalInstance.close([$scope.hostdata, $scope.credentialData]);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.newHostnames = function($event){
            $scope.hostdata.hostnames.push({key:''});
            $event.preventDefault();
        }

    }]);
