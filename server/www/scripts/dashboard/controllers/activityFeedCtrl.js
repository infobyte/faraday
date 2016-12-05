// Faraday Penetration Test IDE
// Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
'use strict';

angular.module('faradayApp')
    .controller('activityFeedCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {
            
            var self = this;
            self.commands = [];
            
            // Get last 5 commands
            var init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getCommands($scope.workspace, 0, 5)
                        .then(function(commands) {
                            self.commands = commands;
                            console.log(commands);
                        });
                }
            };

            dashboardSrv.registerCallback(init);
            init();
            
    }]);