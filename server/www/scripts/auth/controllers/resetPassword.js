// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('resetPassword', ['$modalInstance', '$scope', 'AccountSrv',
        function($modalInstance, $scope, AccountSrv) {

        // Change Password Modal controller

        $scope.data;

        init = function () {
        	$scope.data = {
                "current":  "",
                "newPassword": "",
                "newPasswordRepeat": ""
        	};
        };

        $scope.open = function($event, isStart) {
            $event.preventDefault();
            $event.stopPropagation();
        };

        $scope.ok = function(){
            AccountSrv.changePassword($scope.data).then(
                    function(response, statusText, xhrObj){
                        $modalInstance.close()
                }, function(xhrObj, textStatus, err) {
                    if (xhrObj.data.response.errors.password != undefined) {
                        $scope.form.current.$setValidity("current", false);
                    }
                    if (xhrObj.data.response.errors.new_password_confirm != undefined) {
                        $scope.form.password.$setValidity("password", true);
                        $scope.form.passRepeat.$setValidity("passRepeat", false);
                    }
                });
        };

        $scope.resetError = function() {
            $scope.form.current.$setValidity('current', true);

        }

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);