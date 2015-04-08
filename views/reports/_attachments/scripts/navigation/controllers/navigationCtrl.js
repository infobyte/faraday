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
        $http.get('/reports/_design/reports/scripts/config/config.json').then(function(conf){
            var dt_expiration = new Date(conf.data.cdate);
            var today = new Date(),
                dt_days;

            dt_expiration.setFullYear(dt_expiration.getFullYear()+1);
            var timeDiff = Math.abs(dt_expiration.getTime() - today.getTime());
            var diffDays = Math.ceil(timeDiff / (1000 * 3600 * 24));
            if (diffDays < 30){
                $scope.expiration = "Your current license is due to expire soon.</br>Please visit <a href='https://www.faradaysec.com/users/' target='_blank'>https://www.faradaysec.com/users/</a> to extend your license before it expires.";
            }else if(today > dt_expiration){
                $scope.expiration = "Your license has expired.</br>Please visit <a href='https://www.faradaysec.com/users/' target='_blank'>https://www.faradaysec.com/users/</a> to extend your license.";
            }
        });

	}]);
