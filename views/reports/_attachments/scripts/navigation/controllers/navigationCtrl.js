angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$route', '$routeParams', '$cookieStore', '$location',
        function($scope, $route, $routeParams, $cookieStore, $location) {

            $scope.$on('$routeChangeSuccess', function(){
                if($routeParams.wsId != undefined) {
                    $scope.workspace = $routeParams.wsId;
                    $cookieStore.put('currentUrl', $location.path());
                }
            });

	}]);
