// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesModalNew', ['$modalInstance', '$scope',
        function($modalInstance, $scope) {

        $scope.minDate;
        $scope.dateOptions;
        $scope.workspace;

        init = function () {
        	$scope.workspace = {};
        };

        $scope.okNew = function(){
            $modalInstance.close($scope.workspace);
        };

        $scope.cancel = function() {
            $modalInstance.close();
        };

        init();
    }]);