// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$http','$route', '$routeParams', '$cookies', '$location',
        function($scope, $http, $route, $routeParams, $cookies, $location) {

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

        if(navigator.userAgent.toLowerCase().indexOf('iceweasel') > -1) {
             $scope.isIceweasel = "Your browser is not supported, please use Firefox or Chrome";
        }
        
	}]);
