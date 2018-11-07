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
                    if ($routeParams.wsId !== undefined) {
                        $scope.workspace = $routeParams.wsId;

                        $scope.isExpanded = false;
                        $scope.hideEmpty = false;

                        collapse();

                        dashboardSrv.getActivityFeed($scope.workspace)
                            .then(function (response) {
                                vm.commands = response.activities;
                            });
                    }
                };

                $scope.toggleExpanded = function () {
                    if ($scope.isExpanded) {
                        collapse();
                    } else {
                        expand();
                    }
                };

                var collapse = function () {
                    $scope.cmdLimit = 5;
                    $scope.isExpanded = false;
                    $scope.hideEmpty = false;
                    angular.element('#first-row-panel').css('display', 'inherit');
                    angular.element('#activities-container-row').addClass('mt-md');
                };

                var expand = function () {
                    $scope.cmdLimit = 15; // Should be a constant
                    $scope.isExpanded = true;
                    angular.element('#first-row-panel').css('display', 'none');
                    angular.element('#activities-container-row').removeClass('mt-md');
                };

                $scope.isEmpty = function (cmd) {
                    return cmd.hosts_count === 0 && cmd.services_count === 0 && cmd.vulnerabilities_count === 0;
                };

                dashboardSrv.registerCallback(init);
                init();
            }]);