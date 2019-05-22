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
            'target': '',
            'hostsIp': {},
            'targetsArray': []
        };

        $scope.total_rows = 0;
        $scope.pageSize = 5;
        $scope.currentPage = 1;
        $scope.newCurrentPage = {};
        $scope.targetFilter = {};
        $scope.activeSearch;

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

        $scope.invalidSubmit = function() {
            if($scope.showTargets() === true){
                if($scope.credentialData.targetsArray.length > 0) {
                    return false;
                } else {
                    return true;
                }
            } else {
                return false;
            }
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

        $scope.filterTargets = function() {
            var filter = {ip: $scope.targetFilter.ip};
            targetFactCred.getTargets($scope.workspace, $scope.currentPage, $scope.pageSize, filter).then(function(targets){
                $scope.targets = targets.hosts;
                $scope.activeSearch = true;
            });
        };

        $scope.clearFilterTargets = function() {
            $scope.activeSearch = false;
            targetFactCred.getTargets($scope.workspace, $scope.currentPage, $scope.pageSize).then(function(targets){
                $scope.targets = targets.hosts;
                $scope.targetFilter = {};
            });
        };

        $scope.assignTarget = function(target, hostIp) {
            // Receive hostIp as parameter because if target
            // is Service, it does not have hostIp
            var index = -1;
            var array = $.grep($scope.credentialData.targetsArray, function(item, i){
                index = i;
                return item.id === target.id && item.type === target.type;
            });

            if(array.length > 0) {
                // Remove target selection
                $scope.credentialData.targetsArray.splice(index, 1);
            } else {
                $scope.credentialData.targetsArray.push(target);

                // Since it is not possible to obtain the hostIp from target if it is a service,
                // credentialData.hostsIp contains the host's id with its IP if target is service
                if(target.type === "Service")
                    $scope.credentialData.hostsIp[target.host_id] = hostIp;
            }
        };

        $scope.updatePaginator = function(isNext, toGo) {
            if (isNext === true)
                $scope.currentPage = $scope.currentPage + 1;
            else if (toGo) {
                $scope.currentPage = toGo;
            } else {
                $scope.currentPage =  $scope.currentPage - 1;
            }

            targetFactCred.getTargets($scope.workspace, $scope.currentPage, $scope.pageSize).then(function(targets){
                $scope.targets = targets.hosts;
            });

        };

        $scope.go = function() {
            $scope.currentPage = 1;
            if($scope.newCurrentPage.value <= (parseInt($scope.total_rows/$scope.pageSize) + 1) && $scope.newCurrentPage.value > 0) {
                $scope.currentPage = $scope.newCurrentPage.value;
            }

            $scope.updatePaginator(false, $scope.currentPage);
        };

        $scope.isEmpty = function(obj) {
            for(var key in obj) {
                if(obj.hasOwnProperty(key))
                    return false;
            }
            return true;
        };

        init();
}]);
