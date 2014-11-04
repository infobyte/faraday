angular.module('faradayApp')
    .controller('modalDeleteCtrl', function($scope, $modalInstance, amount) {
        if(amount == 1) {
            $scope.message = "A vulnerability will be deleted.";
        } else {
            $scope.message = amount + " vulnerabilities will be deleted.";
        }
        $scope.message += " This action cannot be undone. Are you sure you want to proceed?";

        $scope.ok = function() {
            $modalInstance.close();
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    });
