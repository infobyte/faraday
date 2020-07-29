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

                    $scope.settings = {
                        currentPage: 0,
                        offset: 0,
                        pageLimit: 5,
                        pageLimits: ['3', '5', '10', '20', '30', '50', '80', '100']
                    };

                    if ($routeParams.wsId !== undefined) {
                        $scope.workspace = $routeParams.wsId;

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
                    $scope.settings.pageLimit = 5;
                    $scope.isExpanded = false;
                    $scope.hideEmpty = true;
                    angular.element('#first-row-panel').css('display', 'inherit');
                    angular.element('#activities-container-row').addClass('mt-md');
                };

                var expand = function () {
                    $scope.settings.pageLimit =  15;
                    $scope.isExpanded = true;
                    $scope.hideEmpty = false;
                    angular.element('#first-row-panel').css('display', 'none');
                    angular.element('#activities-container-row').removeClass('mt-md');
                };

                $scope.isEmpty = function (cmd) {
                    return cmd.hosts_count === 0 && cmd.services_count === 0 && cmd.vulnerabilities_count === 0;
                };

                $scope.getValidCount = function () {
                    var count = 0;
                    for(var i = 0; i < vm.commands.length; i++){
                        if (!$scope.isEmpty(vm.commands[i])) count ++
                    }
                    return count;
                };

                $scope.fitStringInTooltip = function (string) {
                    /**
                     * Summary: split string to fit it into tooltip.
                     * */
                    if (string.length >= 18)
                        return string.substring(0, 18) + ' ' + string.substring(18)
                    else
                        return string
                };

                dashboardSrv.registerCallback(init);
                init();
            }]);