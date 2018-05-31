// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .controller('credentialsCtrl',
        ['$scope', '$filter', '$q', '$uibModal', '$routeParams', '$window', 'commonsFact', 'credential', 'ServerAPI', 'workspacesFact',
        function($scope, $filter, $q, $uibModal, $routeParams, $window, commonsFact, credential, ServerAPI, workspacesFact) {

            $scope.workspace;
            $scope.workspaces;
            $scope.credentials = [];
            // Contains: type of parent(Host or Service), id(Couchid and internal id) of that and name of host and/or name of service(For show in view)
            $scope.parentObject = new Object();

            // table stuff
            $scope.reverse;
            $scope.search;
            $scope.selectall_credentials;
            $scope.sort_field;

            var getParent = function() {

                var deferred = $q.defer();

                // Host is our parent.
                if($routeParams.hId !== undefined){

                    // Load all host information needed.
                    $scope.parentObject.parent_type = 'Host';
                    $scope.parentObject.id = $routeParams.hId;

                    ServerAPI.getObj($scope.workspace, $scope.parentObject.id, 'hosts').then(function (response) {
                        $scope.parentObject.nameHost = response['data']['name'];
                        deferred.resolve();
                    });
                }

                 // Service is our parent.
                if($routeParams.sId !== undefined){

                    // Load all service information needed.
                    $scope.parentObject.parent_type = 'Service';
                    $scope.parentObject.id = $routeParams.sId;

                    ServerAPI.getObj($scope.workspace, $scope.parentObject.id, 'services').then(function (response) {
                        $scope.parentObject.nameService = response['data']['name'];

                        // and also, load all host information needed.
                        var hostId = response['data']['host_id'];

                        ServerAPI.getObj($scope.workspace, hostId, 'hosts').then(function (response) {
                            $scope.parentObject.nameHost = response['data']['name'];
                            deferred.resolve();
                        });
                    });
                }
                // We dont have parent, resolve promise.
                deferred.resolve();
                return deferred.promise;
            };

            var loadCredentials = function (credentials){
                credentials.forEach(function(cred){
                    
                    var object = new credential(cred.value, cred.value.parent, cred.value.parent_type);
                    object.getParentName($scope.workspace).then(function(response){
                        object.target = response;
                    });
                    $scope.credentials.push(object);

                });
            };

            var getAndLoadCredentials = function() {
 
                // Load all credentials, we dont have a parent.
                if($scope.parentObject.parent_type === undefined){
                    ServerAPI.getCredentials($scope.workspace).then(function(response){
                        loadCredentials(response.data.rows);
                    });
                }
                else {
                    // Load all credentials, filtered by host internal id or service internal id.
                    if ($scope.parentObject.parent_type === 'Host')
                        var data = {'host_id': $scope.parentObject.id};
                    else if ($scope.parentObject.parent_type === 'Service')
                        var data = {'service_id': $scope.parentObject.id};

                    ServerAPI.getCredentials($scope.workspace, data).then(function(response){
                        loadCredentials(response.data.rows);
                    });
                }
            };

            var init = function() {

                // table stuff
                $scope.selectall_credentials = false;
                $scope.sort_field = "end";
                $scope.reverse = true;

                // Load all workspaces to list 'choose workspace'
                workspacesFact.list().then(function(wss) {
                    $scope.workspaces = wss;
                });

                $scope.workspace = $routeParams.wsId;

                getParent().then(function(){
                    getAndLoadCredentials();
                });
            };

            var removeFromView = function(credential){
                $scope.credentials.forEach(function(item, index){
                    if (item._id === credential._id)
                        $scope.credentials.splice(index, 1);     
                });
            };

            // Delete to server.
            var remove = function(credentialsToDelete) {

                var confirmations = [];

                credentialsToDelete.forEach(function(credToDelete) {
                    var deferred = $q.defer();

                    $scope.credentials.forEach(function(credentialLocal){
                        if(credentialLocal._id == credToDelete._id){
                            credentialLocal.delete($scope.workspace).then(function(resp) {
                                deferred.resolve(resp);
                                removeFromView(credentialLocal);
                            }, function(message) {
                                deferred.reject(message);
                            });
                            confirmations.push(deferred);
                        }
                    });
                });
                return $q.all(confirmations);
            };

            var createCredential = function(credentialData, parent_id, parent_type){
                // Add parent id, create credential and save to server.
                try {
                    var credentialObj = new credential(credentialData, parent_id, parent_type);
                    
                    credentialObj.create($scope.workspace).then(function(){
                         $scope.credentials.push(credentialObj);
                    }, function(){
                        console.log('Error creating credential.');
                    });

                } catch (error) {
                    console.log(error);
                }
            };

            var editCredential = function(credentialEdited, idCredentialEdited){
                $scope.credentials.forEach(function(item, index){
                    if (item._id === idCredentialEdited){
                        item.name =  credentialEdited.name;
                        item.username = credentialEdited.username;
                        item.password = credentialEdited.password;
                        item.update($scope.workspace);
                    }
                });
            };

            // Binded to New button.
            $scope.new = function() {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/credentials/partials/modalNewEdit.html',
                    controller: 'modalNewEditCredentialCtrl',
                    size: 'lg',
                    resolve: {
                        title: function(){
                            return 'New credential';
                        },
                        credential: function(){
                            return undefined;
                        }
                    }
                 });
                modal.result
                    .then(function(data) {
                       createCredential(data, $scope.parentObject.id, $scope.parentObject.parent_type);
                    });
            };

            // Binded to Edit button.
            $scope.edit = function() {

                var credentialToEdit = $scope.selectedCredentials()[0];
                
                var modal = $uibModal.open({
                    templateUrl: 'scripts/credentials/partials/modalNewEdit.html',
                    controller: 'modalNewEditCredentialCtrl',
                    size: 'lg',
                    resolve: {
                        title: function(){
                            return 'Edit credential';
                        },
                        credential: function(){
                            return credentialToEdit;
                        }
                    }
                 });

                modal.result
                    .then(function(data) {
                       editCredential(data, credentialToEdit._id);
                    });
            };

            // Binded to Delete button, internal logic.
            $scope.delete = function() {
                var selected = $scope.selectedCredentials();

                var message = "A credential will be deleted";
                if(selected.length > 1) {
                    message = selected.length  + " credentials will be deleted";
                }
                message = message.concat(". This operation cannot be undone. Are you sure you want to proceed?");
                $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            return message;
                        }
                    }
                }).result.then(function() {
                    remove(selected);
                }, function() {
                    //dismised, do nothing
                });
            };

            $scope.selectedCredentials = function() {
                var selected = [];

                $filter('filter')($scope.credentials, $scope.search).forEach(function(credential) {
                    if(credential.selected === true) {
                        selected.push(credential);
                    }
                });

                return selected;
            };

            $scope.checkAll = function() {
                $scope.selectall_credentials = !$scope.selectall_credentials;

                var tmp_credentials = $filter('filter')($scope.credentials, $scope.search);
                tmp_credentials.forEach(function(credential) {
                    credential.selected = $scope.selectall_credentials;
                });
            };

            // toggles sort field and order
            $scope.toggleSort = function(field) {
                $scope.toggleSortField(field);
                $scope.toggleReverse();
            };

            // toggles column sort field
            $scope.toggleSortField = function(field) {
                $scope.sort_field = field;
            };

            // toggle column sort order
            $scope.toggleReverse = function() {
                $scope.reverse = !$scope.reverse;
            };

            $scope.reloadPage = function() {
                $window.location.reload();
            };

            init();
    }]);
