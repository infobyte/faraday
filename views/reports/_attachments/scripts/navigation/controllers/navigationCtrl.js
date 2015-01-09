angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$route', '$routeParams',
        function($scope, $route, $routeParams) {

            $scope.$on('$routeChangeSuccess', function(){
                $scope.workspace = $routeParams.wsId;
            });

	}]);
