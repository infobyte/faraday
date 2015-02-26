angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$route', '$routeParams', '$cookies', '$location',
        function($scope, $route, $routeParams, $cookies, $location) {

        $scope.workspace = "";

        $scope.$on('$routeChangeSuccess', function(){
            if($routeParams.wsId != undefined) {
                $scope.workspace = $routeParams.wsId;
                $cookies.currentUrl = $location.path();
            }
        });

        $scope.loadCurrentWorkspace = function() {
            var pos = -1;

            if($cookies.currentUrl != undefined) {
                pos = $cookies.currentUrl.indexOf('ws/');
            }

            if($routeParams.wsId != undefined) {
                $scope.workspace = $routeParams.wsId;
            } else if(pos >= 0) {
                $scope.workspace = $cookies.currentUrl.slice(pos+3);
            }
        };

        $scope.loadCurrentWorkspace();

	}]);
