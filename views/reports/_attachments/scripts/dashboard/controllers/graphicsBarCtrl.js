angular.module('faradayApp')
    .controller('graphicsBarCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.barData = [];
            $scope.treemapData = [];
            $scope.cakeData = [];

            if (workspace != undefined){
                dashboardSrv.getHostsByServicesCount(workspace).then(function(res){
                    if (res.length > 2) {
                        res.sort(function(a, b){
                            return b.value-a.value;
                        });
                        $scope.barData = res.slice(0, 3);
                    }
                });
                
                dashboardSrv.getServicesCount(workspace).then(function(res){
                    if (res.length > 4) {
                        res.sort(function(a, b){
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

                dashboardSrv.getVulnerabilitiesCount(workspace).then(function(res){
                    if (res.length > 0) {
                        var tmp = [
                            {"key": "low", "value": 0, "color": "#A1CE31"},
                            {"key": "med", "value": 0, "color": "#DFBF35"},
                            {"key": "high", "value": 0, "color": "#DF3936"},
                            {"key": "critical", "value": 0, "color": "#8B00FF"},
                            {"key": "info", "value": 0, "color": "#428BCA"}
                        ];

                        function accumulate(_array, key, value){
                            _array.forEach(function(obj){
                                if (obj.key == key){
                                    obj.value += value;
                                }
                            });
                        }
                        
                        res.forEach(function(tvuln){
                            if (tvuln.key == 1 || tvuln.key == "info"){
                                accumulate(tmp, "info", tvuln.value);
                            } else if (tvuln.key == 2 || tvuln.key == "low") {
                                accumulate(tmp, "low", tvuln.value);
                            } else if (tvuln.key == 3 || tvuln.key == "med") {
                                accumulate(tmp, "med", tvuln.value);
                            } else if (tvuln.key == 4 || tvuln.key == "high") {
                                accumulate(tmp, "high", tvuln.value);
                            } else if (tvuln.key == 5 || tvuln.key == "critical") {
                                accumulate(tmp, "critical", tvuln.value);
                            }
                        });
                        $scope.cakeData = {"children": tmp};
                    }
                });
            }

    }]);
