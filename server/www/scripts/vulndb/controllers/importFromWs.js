angular.module('faradayApp')
    .controller('vulnModelModalImportFromWs',
        ['$scope', '$modalInstance', 'ServerAPI',
        function($scope, $modalInstance, ServerAPI) {
            $scope.workspaces
            $scope.selectedWs
            $scope.data;

            var init = function() {
                ServerAPI.getWorkspacesNames().then(
                    function(ws_data) {
                        $scope.workspaces = ws_data.data.workspaces;
                    }, function(err) {
                        console.log(err);
                    }
                )
            }

            $scope.ok = function() {
                $modalInstance.close($scope.selectedWs);
            };

            $scope.cancel = function() {
                $modalInstance.dismiss('cancel');
            };
            init();
    }]);
