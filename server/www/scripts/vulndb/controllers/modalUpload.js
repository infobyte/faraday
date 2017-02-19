// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulnModelModalUpload',
        ['$scope', '$modalInstance',
        function($scope, $modalInstance) {
            $scope.data;

            $scope._import = function() {
                var csv = document.getElementById('file').files[0];
                $scope.data = csv;
            };

            $scope.ok = function() {
                $modalInstance.close($scope.data);
            };

            $scope.cancel = function() {
                $modalInstance.dismiss('cancel');
            };
    }]);
