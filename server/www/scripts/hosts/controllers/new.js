// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('newHostCtrl', ['$scope', '$routeParams', 'workspacesFact',
                                '$uibModal', 'hostsManager', 'commonsFact', '$location',
            function($scope, $routeParams, workspacesFact, $uibModal, hostsManager,
                     commons, $location){

        init = function(){
            $scope.workspace = $routeParams.wsId;
            $scope.editing = true;
            $scope.showServices = false;

            $scope.interface = {
                "hostnames": [{key: ''}],
                "ipv6": {
                        "prefix": "00",
                        "gateway": "0000.0000.0000.0000",
                        "DNS": [],
                        "address": "0000:0000:0000:0000:0000:0000:0000:0000"
                    },
                "ipv4":{
                        "mask": "0.0.0.0",
                        "gateway": "0.0.0.0",
                        "DNS": [],
                        "address": "0.0.0.0"
                    },
                "mac": "00:00:00:00:00:00",
                "interfaceOwner": "",
                "interfaceOwned": false
            };
            $scope.host = {
                "name": "",
                "description": "",
                "default_gateway": "None",
                "os": "",
                "owned": false,
                "owner": "",
            };

            // load all workspaces
            workspacesFact.list()
                .then(function(wss) {
                    $scope.workspaces = wss;
                });

            $scope.newHostnames = function($event){
                $scope.interface.hostnames.push({key:''});
                $event.preventDefault();
            };

            $scope.insert = function(hostdata, interfaceData) {
                var interfaceData = $scope.createInterface(hostdata, interfaceData);
                hostsManager.createHost(hostdata, interfaceData, $scope.workspace).then(function(host) {
                    $location.path('/host/ws/' + $scope.workspace + '/hid/' + $scope.host._id);
                }, function(message) {
                    $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        size: 'sm',
                        resolve: {
                            msg: function() {
                                return message;
                            }
                        }
                    });
                });
            };

            $scope.ok = function(){
                var interface = angular.copy($scope.interface);
                interface.hostnames = commons.objectToArray(interface.hostnames);
                $scope.insert($scope.host, interface);
            };

            $scope.createInterface = function (hostData, interfaceData){
                if(typeof(hostData.ipv4) == "undefined") hostData.ipv4 = "";
                if(typeof(hostData.ipv6) == "undefined") hostData.ipv6 = "";
                var interfaceData = {
                    "_id": CryptoJS.SHA1(hostData.name).toString() + "." + CryptoJS.SHA1("" + "._." + interfaceData.ipv4 + "._." + interfaceData.ipv6).toString(),
                    "description": "",
                    "hostnames": interfaceData.hostnames,
                    "ipv4": interfaceData.ipv4,
                    "ipv6": interfaceData.ipv6,
                    "mac": interfaceData.mac,
                    "metadata": {
                        "update_time": new Date().getTime(),
                        "update_user": "",
                        "update_action": 0,
                        "creator": "",
                        "create_time": new Date().getTime(),
                        "update_controller_action": "",
                        "owner": "",

                    },
                    "name": hostData.name,
                    "network_segment": "",
                    "owned": false,
                    "owner": "",
                    "parent": CryptoJS.SHA1(hostData.name).toString(),
                    "ports": {
                       "filtered": 0,
                       "opened": 0,
                       "closed": 0
                    },
                    "type": "Interface"
                };
                return interfaceData;
            };

        };

        init();

    }]);

