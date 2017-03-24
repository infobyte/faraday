// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('vulndbModalCreateDB',
        ['$scope', '$modalInstance', 'vulnModelsManager',
        function($scope, $modalInstance, vulnModelsManager) {

        $scope.message;

        var init = function() {
            $scope.message = "It looks like your Faraday installation is missing "+
                             "the Vulnerability Model database. Would you like to create it now?";
        };

        $scope.yes = function() {
            vulnModelsManager.createDB()
                .then(function() {
                    $modalInstance.close();
                    $modalInstance.dismiss();
                }, function() {
                    $scope.message = "There's been a problem creating the database.";
                });
        };

        $scope.no = function() { };

        init();
    }]);
