// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesModalCreateDB',
        ['$scope', '$modalInstance', 'licensesManager',
        function($scope, $modalInstance, licensesManager) {

        $scope.message;

        init = function() {
            $scope.message = "It looks like your Faraday installation is missing "+
                             "the Licenses database. Would you like to create it now?";
        };

        $scope.yes = function() {
            licensesManager.createDB()
                .then(function() {
                    $modalInstance.close($scope.data);
                }, function() {
                    $scope.message = "There's been a problem creating the database.";
                });
        };

        $scope.no = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
    }]);
