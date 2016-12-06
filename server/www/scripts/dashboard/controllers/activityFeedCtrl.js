// Faraday Penetration Test IDE
// Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

'use strict';

angular.module('faradayApp')
    .controller('activityFeedCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {
            
            var vm = this;
            vm.commands = [];
            
            // Get a count of all hosts created by this command.
            vm.getHostCount = function(command){
                dashboardSrv.getHostsCountByCommandId($scope.workspace, command._id)
                        .then(function(hosts) {

                           if( !isNaN(hosts['total_rows']) ){
                               command['hosts_count'] = hosts['total_rows'];
                           }
                        });
            };

            // Get a count of all services created by this command.
            vm.getServiceCount = function(command){
                dashboardSrv.getServicesByCommandId($scope.workspace, command._id)
                        .then(function(services) {
                            
                            if( services['services'].length != 0 ){
                                command['services_count'] = services['services'].length;
                            }
                        });
            };

            // Get a count of all vulns created by this command.
            vm.getVulnsCount = function(command){
                dashboardSrv.getVulnsByCommandId($scope.workspace, command._id)
                        .then(function(vulnerabilities) {
                            
                            if( !isNaN(vulnerabilities['count']) ){
                                command['vulnerabilities_count'] = vulnerabilities['count'];
                            }
                        });
            };
            
            // Get last 5 commands
            var init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getCommands($scope.workspace, 0, 5)
                        .then(function(commands) {

                            vm.commands = commands;
                            vm.commands.forEach(function(command){
                              vm.getHostCount(command);
                              vm.getServiceCount(command);
                              vm.getVulnsCount(command);
                            });
                        });
                }
            };

            dashboardSrv.registerCallback(init);
            init();
    }]);