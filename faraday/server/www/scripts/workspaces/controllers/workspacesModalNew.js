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
        	$scope.workspace = {
                "description":  "",
                "name":         "",
                "scope":        [{key: ''}]
        	};
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

        $scope.newScope = function($event){
            $scope.workspace.scope.push({key:''});
            $event.preventDefault();
        }

        $scope.okNew = function(){
            $modalInstance.close($scope.workspace);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
