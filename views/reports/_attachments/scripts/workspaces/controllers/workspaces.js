angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact',
            function($scope, workspacesFact) {
        workspacesFact.get(function(wss) {
            $scope.wss = wss;
        });
        
        $scope.insert = function(workspace){
            $scope.wss.push(workspace.name);
        };
    }]);
