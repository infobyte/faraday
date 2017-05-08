// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .controller('modalNewEditCredentialCtrl',
        ['$scope', '$modalInstance', 'title', 'credential',
        function($scope, $modalInstance, title, credential) {

        $scope.title = title;

        $scope.credentialData = {
            'name': '',
            'username': '',
            'password': ''
        };
        
        var init = function(){
            if(credential !== undefined){
                $scope.credentialData.name = credential.name;
                $scope.credentialData.username = credential.username;
                $scope.credentialData.password = credential.password;
            }
        };

        $scope.ok = function() {
             $modalInstance.close($scope.credentialData);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        init();
}]);