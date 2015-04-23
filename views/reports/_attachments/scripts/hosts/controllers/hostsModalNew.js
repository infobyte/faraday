// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsModalNew',
        ['$scope', '$modalInstance', 'hostsManager',
        function($scope, $modalInstance, hostsManager) {

        $scope.hostdata = {};

        $scope.ok = function() {
            if($scope.hostdata.default_gateway.ip == undefined) $scope.hostdata.default_gateway.ip = "";
            if($scope.hostdata.default_gateway.mac == undefined) $scope.hostdata.default_gateway.mac = "";
            if($scope.hostdata.os == undefined) $scope.hostdata.os = "";
            if($scope.hostdata.owned == undefined) $scope.hostdata.owned = false;
            if($scope.hostdata.owner == undefined) $scope.hostdata.owner = "";
            if($scope.hostdata.parent == undefined) $scope.hostdata.parent = null;
            
            $scope.hostdata.default_gateway = [$scope.hostdata.default_gateway.ip, $scope.hostdata.default_gateway.mac];

            $modalInstance.close($scope.hostdata);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
