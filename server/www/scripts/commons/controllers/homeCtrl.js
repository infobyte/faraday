// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('homeCtrl',
        ['$location', 'loginSrv',
        function($location, loginSrv) {
            loginSrv.isAuthenticated().then(function(auth){
                if(!auth) {
                    $location.path('/login');
                }
                return deferred.reject(response);
            });
        }]);