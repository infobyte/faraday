angular.module('faradayApp')
    .controller('graphicsBarCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.barData = [];

            if (workspace != undefined){
                dashboardSrv.getHostsByServicesCount(workspace).then(function(res){
                    if (res.length > 2) {
                        var a = res.sort(function(a, b){
                            return b.value-a.value;
                        })
                        $scope.barData = res.slice(0, 3);
                    }
                });
                
            }

            // $scope.barOnMouseOver = function(item){
            //     $scope.barTooltip = "lala";
            //     $scope.$apply(function() {
            //         dashboardSrv.getHostName(item.value).then(function(hostname){
            //             $scope.barTooltip = "Host: " + hostname + "Value: " + item.key;
            //         })
            //     }); 
            // }

    }]);
