// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesModalEdit',
        ['$scope', '$modalInstance', 'License', 'license',
        function($scope, $modalInstance, License, license) {

        $scope.data;
        $scope.openedStart;
        $scope.openedEnd;

        var init = function() {
            $scope.data = new License;
            $scope.data.set(license);

            $scope.data.end = new Date(license.end);
            $scope.data.start = new Date(license.start);
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
