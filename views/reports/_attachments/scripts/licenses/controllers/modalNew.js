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

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.ok = function() {
            $modalInstance.close($scope.data);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
