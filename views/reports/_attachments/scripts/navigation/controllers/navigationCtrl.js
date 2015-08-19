// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('navigationCtrl', ['$scope', '$http','$route', '$routeParams', '$cookies', '$location', '$interval',
        function($scope, $http, $route, $routeParams, $cookies, $location, $interval) {

        $scope.workspace = "";
        $scope.component = "";

        $scope.checkCwe = function() {
            $http.get("https://www.faradaysec.com/scripts/updatedb.php").then(function() {
            }, function() {
                console.log("CWE database couldn't be updated");
            });
        };

        var timer = $interval($scope.checkCwe, 43200000);

        $scope.$on('$destroy', function() {
            $interval.cancel(timer);
        });

        $scope.$on('$routeChangeSuccess', function() {
            $scope.updateWorkspace();
            $scope.updateComponent();
        });

        $scope.updateWorkspace = function() {
            if($routeParams.wsId != undefined) {
                $scope.workspace = $routeParams.wsId;
                $cookies.currentUrl = $location.path();
            }
        };

        $scope.updateComponent = function() {
            if($location.path() == "") {
                $scope.component = "home";
            } else {
                $scope.component = $location.path().split("/")[1];
            }
            $cookies.currentComponent = $scope.component;
        };

        $scope.showNavigation = function() {
            var noNav = ["home", "index", ""];
            return noNav.indexOf($scope.component) < 0;
        };

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
        $scope.checkCwe();

        if(navigator.userAgent.toLowerCase().indexOf('iceweasel') > -1) {
             $scope.isIceweasel = "Your browser is not supported, please use Firefox or Chrome";
        }
        
	}]);
