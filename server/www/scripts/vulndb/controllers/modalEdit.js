// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulndDbModalEdit',
                ['$scope', '$modalInstance', 'VulnModel', 'model', 'EXPLOITATIONS',
                 function($scope, $modalInstance, VulnModel, model, EXPLOITATIONS) {

        $scope.data;
        $scope.openedStart;
        $scope.openedEnd;

        var init = function() {
            $scope.exploitations = EXPLOITATIONS
            $scope.data = new VulnModel;
            $scope.data.set(model);
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
