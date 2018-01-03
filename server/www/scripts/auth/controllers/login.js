// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('loginCtrl', ['$scope', '$location', '$cookies', 'loginSrv', function($scope, $location, $cookies, loginSrv) {

        $scope.data = {
            "user": null,
            "pass": null
        };

        $scope.errorLoginFlag = false;

        $scope.checkResetError = function(){
            if($scope.errorLoginFlag == true)
                $scope.errorMessage = "";
        };

        $scope.login = function(){
            if ($scope.data.user && $scope.data.pass){
                loginSrv.login($scope.data.user, $scope.data.pass).then(function(user){
                    var currentUrl = "";
                    if($cookies.currentUrl != undefined) {
                        currentUrl = $cookies.currentUrl;
                    }
                    $location.path(currentUrl);
                }, function(){
                    $scope.errorMessage = "Invalid user or password";
                    $scope.errorLoginFlag = true;
                });
            } else {
                $scope.errorMessage = "Every field is required";
                $scope.errorLoginFlag = true;
            }
        };

        $scope.$on('$routeChangeSuccess', function(){
            loginSrv.isAuthenticated().then(function(auth){
                if(auth) $location.path('/');
            });
        });

    }]);

angular.module('faradayApp')
    .controller('loginBarCtrl', ['$scope', '$location', '$cookies','loginSrv', function($scope, $location, $cookies,loginSrv) {
        $scope.user = null;
        $scope.auth = loginSrv.isAuth();

        $scope.$watch(loginSrv.isAuth, function(newValue) {
            loginSrv.getUser().then(function(user){
                $scope.user = user;
                $scope.auth = newValue;
            });
        });

        $scope.getUser = function(){
            return $scope.user;
        };

        $scope.loginPage = function(){
            $location.path('/login');
        };

        $scope.logout = function(){
            loginSrv.logout().then(function(){
                $location.path('/login');
                $cookies.currentUrl = "";
            });
        };
    }]);

angular.module('faradayApp')
    .controller('loginBackgroundCtrl', ['$scope', '$location', '$cookies', function($scope, $location, $cookies) {
        $scope.component = "";
        $scope.isLogin = true;

        $scope.updateComponent = function() {
            if($location.path() == "") {
                $scope.component = "home";
            } else {
                $scope.component = $location.path().split("/")[1];
            }
            $cookies.currentComponent = $scope.component;
            $scope.isLogin = $scope.component == "login";
        };

        $scope.$on('$locationChangeSuccess', function() {
            $scope.updateComponent();
        });
    }]);
