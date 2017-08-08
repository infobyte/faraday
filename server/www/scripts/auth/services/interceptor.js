// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp').
    factory('AuthInterceptor', ['$q', '$location', '$cookies', 'loginSrv', function($q, $location, $cookies, loginSrv){
        return {
            response: function(response){
                return response;
            },
            
            responseError: function(response) {
                if(response.status === 401 || response.status === 403){
                    var deferred = $q.defer();
                    loginSrv.isAuthenticated().then(function(auth){
                        if(!auth) {
                            $location.path('/login');
                            $cookies.currentComponent;
                        }
                        return deferred.reject(response);
                    });
                    return deferred.promise;
                }else{
                    return $q.reject(response);
                }
            }
        }
    }]);
