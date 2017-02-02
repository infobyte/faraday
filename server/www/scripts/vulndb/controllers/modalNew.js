// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnModelModalNew',
        ['$scope', '$modalInstance', 'VulnModel', 'vulnModelsManager',
        function($scope, $modalInstance, VulnModel, vulnModelsManager) {

        $scope.data;
        $scope.models;

        var init = function() {
            $scope.data = new VulnModel;

            $scope.models = vulnModelsManager.models;

            $scope.$watch(function() {
                return $scope.data.model;
            }, function(newVal, oldVal) {
                if(newVal == "Other") {
                    $scope.other = true;
                } else if(oldVal == "Other") {
                    $scope.other = false;
                }
            }, true);
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();

            if(isStart) $scope.openedStart = true; else $scope.openedEnd = true;
        };

        $scope.ok = function() {
            if($scope.other) {
                $scope.data.model = $scope.other_model;
            }

            $modalInstance.close($scope.data);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
