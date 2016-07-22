// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesModalNew',
        ['$scope', '$modalInstance', 'licensesManager',
        function($scope, $modalInstance, licensesManager) {

        $scope.data;
        $scope.other = false;
        $scope.other_product;
        $scope.products;

        init = function() {
            $scope.data = new License;

            $scope.products = licensesManager.products;

            $scope.$watch(function() {
                return $scope.data.product;
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
                $scope.data.product = $scope.other_product;
            }

            $modalInstance.close($scope.data);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
