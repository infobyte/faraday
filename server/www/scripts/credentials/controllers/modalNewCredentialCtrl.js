// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .controller('modalNewCredentialCtrl',
        ['$scope', '$modalInstance',
        function($scope, $modalInstance) {

        $scope.credentialData = {
            'name': '',
            'username': '',
            'password': ''
        };
        
        $scope.ok = function() {
             $modalInstance.close($scope.credentialData);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
}]);