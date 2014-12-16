angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact', function($scope, workspacesFact) {
        workspacesFact.get(function(wss) {
            $scope.wss = wss;
        });
        var hash_tmp = window.location.hash.split("/")[1];
        switch (hash_tmp){
            case "status":
                $scope.hash = "status";
                break;
            default:
                $scope.hash = "";
        }
    }]);
