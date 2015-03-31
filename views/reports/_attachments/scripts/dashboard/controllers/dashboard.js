// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('dashboardCtrl', 
        ['$scope', '$filter', '$route', '$routeParams', 'statusReportFact',
        function($scope, $filter, $route, $routeParams, statusReportFact) {
            //current workspace
            $scope.workspace = $routeParams.wsId;
            $scope.workspaces = [];

            statusReportFact.getWorkspaces().then(function(wss) {
                $scope.workspaces = wss;
            });
    }]);
