// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesModalNew',
        ['$scope', '$modalInstance', 'licensesManager',
        function($scope, $modalInstance, licensesManager) {

        $scope.data;
        $scope.products;

        init = function() {
            $scope.data = new License;

            $scope.products = licensesManager.products;
        };

        $scope.ok = function() {
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            $scope.interfaceData.licensenames.forEach(function(hname){
                licensenames.push(hname.licensename);
            });

            $scope.interfaceData.licensenames = licensenames.filter(Boolean);
            $scope.licensedata.interfaceName = $scope.licensedata.name;
            $scope.licensedata.metadata = {
                "update_time": timestamp,
                "update_user":  "",
                "update_action": 0,
                "creator": "",
                "create_time": timestamp,
                "update_controller_action": "UI Web New",
                "owner": ""
            };

            $modalInstance.close($scope.data);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
