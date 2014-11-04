angular.module('faradayApp')
    .controller('modalKoCtrl', function($scope, $modalInstance, msg) {
        $scope.msg = msg;

        $scope.ok = function() {
            $modalInstance.close();
        };
    });
