// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('lastVulnsCtrl',
        ['$scope', '$routeParams', 'vulnsManager',
        function($scope, $routeParams, vulnsManager) {
            $scope.vulns;
            $scope.vulnSortField = "metadata.create_time";
            $scope.vulnSortReverse = true;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    vulnsManager.getVulns($scope.workspace)
                        .then(function(vulns) {
                            $scope.vulns = vulns;
                        });
                }
            };

            // toggles sort field and order
            $scope.vulnToggleSort = function(field) {
                $scope.vulnToggleSortField(field);
                $scope.vulnToggleReverse();
            };

            // toggles column sort field
            $scope.vulnToggleSortField = function(field) {
                $scope.vulnSortField = field;
            };

            // toggle column sort order
            $scope.vulnToggleReverse = function() {
                $scope.vulnSortReverse = !$scope.vulnSortReverse;
            };

            init();
    }]);