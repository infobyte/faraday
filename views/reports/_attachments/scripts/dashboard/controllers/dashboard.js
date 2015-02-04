angular.module('faradayApp')
    .controller('dashboardCtrl', 
        ['$scope', '$filter', '$route', '$routeParams', 'statusReportFact',
        function($scope, $filter, $route, $routeParams, statusReportFact) {
            //current workspace
            $scope.workspace = $routeParams.wsId;
            $scope.workspaces = [];

            statusReportFact.getWorkspaces(function(wss) {
                $scope.workspaces = wss;
            });
    }]);
