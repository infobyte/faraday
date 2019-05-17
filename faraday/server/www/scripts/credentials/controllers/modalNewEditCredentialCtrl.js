// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .controller('modalNewEditCredentialCtrl',
        ['$scope', '$modalInstance', 'title', 'credential', 'targetFactCred', '$routeParams',
        function($scope, $modalInstance, title, credential, targetFactCred, $routeParams) {
        $scope.title = title;
        $scope.workspace = $routeParams.wsId;
        $scope.targets = [];
        $scope.credentialData = {
            'name': '',
            'username': '',
            'password': '',
            'hostSelectedId': '',
            'serviceSelectedId': '',
            'target': ''
        };

        $scope.targetsArray = [];
        $scope.total_rows = 0;
        $scope.pageSize = 5;
        $scope.currentPage = 1;

        var init = function(){
            if(credential !== undefined){
                $scope.credentialData.name = credential.name;
                $scope.credentialData.username = credential.username;
                $scope.credentialData.password = credential.password;
            }

            targetFactCred.getTargets($scope.workspace, $scope.currentPage, $scope.pageSize).then(function(targets){
                $scope.targets = targets.hosts;
                $scope.total_rows = targets.total;
            });
        };

        $scope.ok = function() {
             $modalInstance.close($scope.credentialData);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };

        $scope.showTargets = function() {
            // Don't show targets in modal:
            // If Credential creation from hosts/services tab
            // If user wants to create credential and not edit it
            if(($routeParams.hId === undefined && $routeParams.sId === undefined) && title === 'New credential'){
                return true;
            }
            else {
                return false;
            }
        };

        $scope.assignTarget = function(target, hostIp) {
            // Receive hostIp as parameter because if target
            // is Service, it does not have hostIp
            var index = -1;
            var array = $.grep($scope.targetsArray, function(item, i){
                index = i;
                return item.id === target.id && item.type === target.type;
            });

            if(array.length > 0) {
                // Remove target selection
                $scope.targetsArray.splice(index, 1);
            }
            else {
                if(target.type === "Host"){
                    $scope.credentialData.hostSelectedId = target.id;
                    $scope.credentialData.target = hostIp;
                    $scope.targetsArray.push(target);
                }
                else if(target.type === "Service") {
                    $scope.credentialData.serviceSelectedId = target.id;
                    $scope.credentialData.target = hostIp + "/" + target.name;
                    $scope.targetsArray.push(target);
                }
            }
        };

        $scope.updatePaginator = function(isNext) {
            if (isNext === true)
                $scope.currentPage = $scope.currentPage + 1;
            else
                $scope.currentPage = $scope.currentPage - 1;

            targetFactCred.getTargets($scope.workspace, $scope.currentPage, $scope.pageSize).then(function(targets){
                $scope.targets = targets.hosts;
            });

        };

        init();
}]);
