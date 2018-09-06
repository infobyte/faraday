// Faraday Penetration Test IDE
// Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

'use strict';

angular.module('faradayApp')
    .controller('activityFeedCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
            function ($scope, $routeParams, dashboardSrv) {

                var vm = this;
                vm.commands = [];

                // Get last 15 commands
                var init = function () {
                    if ($routeParams.wsId != undefined) {
                        $scope.workspace = $routeParams.wsId;
                        $scope.cmdLimit = 5;
                        $scope.isExpanded = false;

                        dashboardSrv.getActivityFeed($scope.workspace)
                            .then(function (response) {
                                vm.commands = response.activities;
                            });
                    }
                };

                $scope.toggleExpanded = function () {
                    var lastVulnPanel = angular.element('#last-vuln-panel');
                    var vulnsByPrice = angular.element('#vulns-by-price');
                    if ($scope.isExpanded) {
                        $scope.cmdLimit = 5;
                        $scope.isExpanded = false;
                        lastVulnPanel.removeClass('slide-up');
                        vulnsByPrice.removeClass('slide-up');
                    }else{
                        $scope.cmdLimit = 15; // Should be a constant
                        $scope.isExpanded = true;
                        lastVulnPanel.addClass('slide-up');
                        vulnsByPrice.addClass('slide-up');
                    }
                };

                dashboardSrv.registerCallback(init);
                init();
            }]);