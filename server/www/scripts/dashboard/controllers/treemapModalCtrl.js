// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('treemapModalCtrl', 
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace',
        function($scope, $modalInstance, dashboardSrv, workspace) {

            dashboardSrv.getServicesCount(workspace).then(function(res) {
                if(res.length > 4) {
                    res.sort(function(a, b) {
                        return b.value - a.value;
                    });
                    var colors = ["#FA5882", "#FF0040", "#B40431", "#610B21", "#2A0A1B"];
                    var tmp = [];
                    res.slice(0, 5).forEach(function(srv) {
                        srv.color = colors.shift();
                        tmp.push(srv);
                    });
                    $scope.treemapDataModel = {"children": tmp, "height":300, "width": 500};
                }
            });

            $scope.ok = function() {
                $modalInstance.close();
            }
    }]);
