angular.module('faradayApp')
    .controller('summarizedCtrl', 
        ['$scope', '$route', '$routeParams', 'dashboardSrv',
        function($scope, $route, $routeParams, dashboardSrv) {
            //current workspace
            var workspace = $routeParams.wsId;
            $scope.servicesCount = [];
            $scope.objectsCount = [];
            $scope.vulnsCount = [];

            if (workspace != undefined){
                dashboardSrv.getServicesCount(workspace).then(function(res){
                    res.sort(function(a, b){
                        return b.value - a.value;
                    });
                    $scope.servicesCount = res;

                });
                dashboardSrv.getObjectsCount(workspace).then(function(res){
                    for(var i = res.length - 1; i >= 0; i--) {
                        if(res[i].key === "interfaces") {
                           res.splice(i, 1);
                        }
                    }
                    $scope.objectsCount = res;
                });
                dashboardSrv.getVulnerabilitiesCount(workspace).then(function(res){
                    if (res.length > 0) {
                        var tmp = [
                            {"key": "critical", "value": 0, "color": "#8B00FF"},
                            {"key": "high", "value": 0, "color": "#DF3936"},
                            {"key": "med", "value": 0, "color": "#DFBF35"},
                            {"key": "low", "value": 0, "color": "#A1CE31"},
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
                        $scope.vulnsCount = tmp;
                    }
                });
            }

    }]);
