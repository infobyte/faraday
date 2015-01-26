angular.module('faradayApp')
    .controller('graphicsBarCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.barData = [];
            $scope.treemapData = [];

            if (workspace != undefined){
                dashboardSrv.getHostsByServicesCount(workspace).then(function(res){
                    if (res.length > 2) {
                        var a = res.sort(function(a, b){
                            return b.value-a.value;
                        });
                        $scope.barData = res.slice(0, 3);
                    }
                });
                
                dashboardSrv.getServicesCount(workspace).then(function(res){
                    if (res.length > 4) {
                        var a = res.sort(function(a, b){
                            return b.value - a.value;
                        });
                        colors = ["#FA5882", "#FF0040", "#B40431", "#610B21", "#2A0A1B"];
                        var tmp = [];
                        res.slice(0, 5).forEach(function(srv){
                            srv.color = colors.shift();
                            tmp.push(srv);
                        });
                        $scope.treemapData = {"children": tmp};
                    }
                });
            }

    }]);
