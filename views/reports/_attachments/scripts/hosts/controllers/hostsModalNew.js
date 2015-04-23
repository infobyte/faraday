// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostsModalNew',
        ['$scope', '$modalInstance', 'usersManager',
        function($scope, $modalInstance, usersManager) {

        $scope.userdata = {};
        $scope.password_repeat;
        $scope.role = null;
        $scope.roles = [
            {name: 'Admin', value:'admin'},
            {name: 'Pentester', value:'pentester'},
            {name: 'Client', value:'client'}
        ]
        $scope.error_message = null;

        $scope.ok = function() {
            if ($scope.userdata.password != $scope.password_repeat){
                $scope.error_message = "Passwords must match";
            } else {
                if ($scope.role != null){
                    $scope.userdata.roles = [$scope.role];
                    $modalInstance.close($scope.userdata);
                }
                $scope.error_message = "A role is needed";
            }
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);
