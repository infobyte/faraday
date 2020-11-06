angular.module('faradayApp').controller('forgotPasswordCtrl', ['$modalInstance', '$scope', 'AccountSrv',
    function($modalInstance, $scope, AccountSrv) {

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.data;

        init = function () {
            $scope.data = {
                "email":  "",
                "recover":{
                    "valid" : false,
                    "not_found": false
                }
            };
        };

        $scope.recover = function(){
            if ($scope.data.email){
                loginSrv.recover($scope.data.email).then(function(result){
                    $scope.data.recover.valid = true;
                    $scope.data.recover.not_found = false;
                    //$modalInstance.close();
                }, function(){
                    $scope.errorMessage = "Invalid email";
                    $scope.data.recover.valid = false;
                    $scope.data.recover.not_found = true;
                });
            } else {
                $scope.errorMessage = "Email user is required";
            }
        };

        init();
}]);
