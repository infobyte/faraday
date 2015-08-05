// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesModalEdit', ['$modalInstance', '$scope', 'ws',
        function($modalInstance, $scope, ws) {
        $scope.minDate;
        $scope.dateOptions;
        $scope.workspace;

        init = function () {
        	$scope.minDate = new Date();
            $scope.dateOptions = {
                formatYear: 'yy',
                startingDay: 1
            };

        	$scope.workspace = angular.copy(ws);
        };

        //DATE PICKER        
        $scope.today = function() {
            $scope.dt = new Date();
        };
        $scope.today();

        $scope.clear = function () {
            $scope.dt = null;
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.okEdit = function() {
            $modalInstance.close($scope.workspace);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);