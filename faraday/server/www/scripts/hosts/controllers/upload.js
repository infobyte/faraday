// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('hostModelModalUpload',
        ['$scope', '$modalInstance',
        function($scope, $modalInstance) {
            $scope.data;
            $scope.fileToUpload = undefined;

            $scope._import = function() {
                $scope.data = $scope.fileToUpload;
                $scope.ok();
            };

            $scope.ok = function() {
                $modalInstance.close($scope.fileToUpload);
            };

            $scope.cancel = function() {
                $modalInstance.dismiss('cancel');
            };
    }]);
