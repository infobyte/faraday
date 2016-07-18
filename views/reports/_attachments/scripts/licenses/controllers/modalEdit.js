// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesModalEdit',
        ['$scope', '$modalInstance', 'licensesManager', 'license',
        function($scope, $modalInstance, licensesManager, license) {

        $scope.data = {};

        init = function() {
            $scope.data = new License;
            angular.copy(license, $scope.data);
        };

        $scope.ok = function() {
            $modalInstance.close($scope.data);
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
