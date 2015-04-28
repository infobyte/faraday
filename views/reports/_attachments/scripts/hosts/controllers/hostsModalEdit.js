// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsModalEdit',
        ['$scope', '$modalInstance', 'hostsManager', 'host',
        function($scope, $modalInstance, hostsManager, host) {

        $scope.hostdata = {};
        $scope.host = {
            "description": host.description,
            "default_gateway": "None",
            "metadata": host.metadata,
            "name": host.name,
            "os": host.os,
            "owner": "",
            "owned": host.owned,
            "parent": host.parent
        };

        $scope.ok = function() {
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            $scope.hostdata = $scope.host;
            $scope.hostdata.metadata['update_time'] = timestamp;
            $scope.hostdata.metadata['update_user'] = "UI Web";

            $modalInstance.close($scope.hostdata);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
