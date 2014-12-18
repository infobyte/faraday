angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact',
            function($scope, workspacesFact) {
        workspacesFact.get(function(wss) {
            $scope.wss = wss;
        });
        
        $scope.insert = function(workspace){
            workspacesFact.put(workspace);
            $scope.wss.push(workspace.name);
        };

        $scope.remove = function(workspace_name){
            delete $scope.wss[$scope.wss.indexOf(workspace_name)]; 
        };
    }]);
