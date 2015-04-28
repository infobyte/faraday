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
            "owner": ""
        };

        $scope.ok = function() {
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            if($scope.hostdata.parent == undefined) $scope.hostdata.parent = null;
            
            $scope.hostdata.metadata = {
                "update_time": timestamp,
                "update_user":  "UI Web",
                "update_action": 0,
                "creator": "UI Web", 
                "create_time": timestamp,
                "update_controller_action": "UI Web New",
                "owner": ""
            };

            $modalInstance.close($scope.hostdata);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
