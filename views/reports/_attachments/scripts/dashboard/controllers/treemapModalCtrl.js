// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('treemapModalCtrl',
        ['$scope', '$modalInstance', 'dashboardSrv', 'workspace',
        function($scope, $modalInstance, dashboardSrv, workspace) {

            dashboardSrv.getTopServices(workspace)
                .then(function(res) {
                    $scope.treemapDataModel = {"children": res, "height":300, "width": 500};
                });

            $scope.ok = function() {
                $modalInstance.close();
            }
    }]);
