// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsModalEdit',
        ['$scope', '$modalInstance', '$routeParams', 'hostsManager', 'host', 'commonsFact',
        function($scope, $modalInstance, $routeParams, hostsManager, host, commons) {

        var ws = $routeParams.wsId; 
        $scope.hostdata = {};
        hostsManager.getInterfaces(ws, host._id).then(function(resp){
            $scope.interface = resp[0].value;
            $scope.interface.hostnames = commons.arrayToObject($scope.interface.hostnames);
        });

        $scope.host = {
            "_id": host._id,
            "_rev": host._rev,
            "description": host.description,
            "default_gateway": "None",
            "metadata": host.metadata,
            "name": host.name,
            "os": host.os,
            "owner": "",
            "owned": host.owned,
            "parent": host.parent,
            "type": host.type
        };

        $scope.ok = function() {
            var date = new Date(),
            timestamp = date.getTime()/1000.0;
            $scope.interface.hostnames = commons.objectToArray($scope.interface.hostnames.filter(Boolean));

            $scope.hostdata = $scope.host;
            $scope.hostdata.metadata['update_time'] = timestamp;
            $scope.hostdata.metadata['update_user'] = "UI Web";

            $modalInstance.close([$scope.hostdata, $scope.interface]);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.newHostnames = function($event){
            $scope.interface.hostnames.push({key:''});
            $event.preventDefault();
        }

    }]);
