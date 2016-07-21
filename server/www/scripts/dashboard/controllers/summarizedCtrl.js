// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('summarizedCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.objectsCount = [];
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;
                    $scope.loadData();

                    $scope.$watch(function() {
                        return dashboardSrv.props.confirmed;
                    }, function() {
                        $scope.loadData();
                    }, true);
                }
            };

            $scope.loadData = function() {
                dashboardSrv.getObjectsCount($scope.workspace)
                    .then(function(obj_count) {
                        $scope.objectsCount = [];
                        for (var property in obj_count) {
                            if (obj_count.hasOwnProperty(property) && obj_count[property] > 0) {
                                var tmp_obj = {};
                                tmp_obj["value"] = obj_count[property];
                                if (property === "std_vulns")
                                    property = "vulns";
                                // replace underscores for spaces
                                tmp_obj["key"] = property.replace("_", " ");
                                $scope.objectsCount.push(tmp_obj);
                            }
                        }
                    });
            };

            init();
    }]);