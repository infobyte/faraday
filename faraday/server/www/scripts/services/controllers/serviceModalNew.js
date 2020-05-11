// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('serviceModalNew', [
        '$scope',
        '$modalInstance',
        '$routeParams',
        'SERVICE_STATUSES',
        'host',
        'servicesManager',
        'hostsManager',
        'commonsFact',
        function ($scope,
                  $modalInstance,
                  $routeParams,
                  SERVICE_STATUSES,
                  host,
                  servicesManager,
                  hostsManager,
                  commonsFact) {

        init = function() {
            $scope.data = {
                "name": "",
                "description": "",
                "owned": false,
                "owner": "",
                "ports": "",
                "protocol": "",
                "parent": "",
                "status": "open",
                "version": ""
            };
            // current Workspace
            var ws = $routeParams.wsId;
            $scope.data.parent = host.id;
            $scope.statuses = SERVICE_STATUSES;
        };

        $scope.ok = function() {
            var date = new Date(),
            timestamp = date.getTime()/1000.0;

            $scope.data.metadata = {
                "update_time": timestamp,
                "update_user":  "",
                "update_action": 0,
                "creator": "",
                "create_time": timestamp,
                "update_controller_action": "UI Web New",
                "owner": ""
            };
            servicesManager.createService($scope.data, $routeParams.wsId).then(function() {
                $modalInstance.close($scope.data);
            }, function(response) {
                if (response.status === 409) {
                    commonsFact.showMessage("Error while creating a new Service " + response.data.name + " Conflicting Vulnarability with id: " + response.data.object._id + ". " + response.data.message);
                } if (response.status === 400) {
                    var field = Object.keys(response.data.messages)[0];
                    var error = response.data.messages[field][0];
                    commonsFact.showMessage("Your input data is wrong,    " + field.toUpperCase() +":      " + error);
                }else {
                    commonsFact.showMessage("Error from backend: " + response.status);
                }
            });
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
