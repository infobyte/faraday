angular.module('faradayApp')
    .controller('graphicsBarCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;

            if (workspace != undefined){
                dashboardSrv.getHostsByServicesCount(workspace).then(function(res){
                    console.log(res);
                    var a = res.sort(function(a, b){
                        return b.value-a.value;
                    })
                    $scope.barData = res.slice(0, 3);
                });
                
            }
    }]);
