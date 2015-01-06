angular.module('faradayApp')
    .controller('workspacesCtrl', ['$scope', 'workspacesFact',
            function($scope, workspacesFact) {
        workspacesFact.get(function(wss) {
            $scope.wss = wss;
        });
        
        $scope.insert = function(workspace){
            workspacesFact.put(workspace, $scope.onSuccessInsert);
        };

        $scope.remove = function(workspace_name){
            workspacesFact.delete(workspace_name);
            delete $scope.wss[$scope.wss.indexOf(workspace_name)]; 
        };

        $scope.onSuccessInsert = function(name){
            $scope.wss.push(name); 
        };
    }]);
