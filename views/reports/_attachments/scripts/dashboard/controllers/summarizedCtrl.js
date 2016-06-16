// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('summarizedCtrl',
        ['$scope', '$routeParams', 'dashboardSrv',
        function($scope, $routeParams, dashboardSrv) {

            $scope.objectsCount;
            $scope.workspace;

            init = function() {
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;

                    dashboardSrv.getObjectsCount($scope.workspace)
                        .then(function(res) {
                            for(var i = res.length - 1; i >= 0; i--) {
                                if(res[i].key === "interfaces") {
                                   res.splice(i, 1);
                                }
                            }
                            $scope.objectsCount = res;
                        });
                }
            };

            init();
    }]);