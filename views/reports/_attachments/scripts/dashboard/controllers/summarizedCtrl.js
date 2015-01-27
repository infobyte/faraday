angular.module('faradayApp')
    .controller('summarizedCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.servicesCount = [];

            if (workspace != undefined){
                dashboardSrv.getServicesCount(workspace).then(function(res){
                    res.sort(function(a, b){
                        return b.value - a.value;
                    });
                    $scope.servicesCount = res;

                });
            }

    }]);
