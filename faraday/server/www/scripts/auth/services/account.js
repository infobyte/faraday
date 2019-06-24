// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp').
    factory('AccountSrv', ["BASEURL", 'ServerAPI', function(BASEURL, ServerAPI){
        return {
            changePassword: function(data) {
                api_data = {
                    "new_password": data.newPassword,
                    "new_password_confirm": data.newPasswordRepeat,
                    "password": data.current
                }
                return ServerAPI.changePassword(api_data);
            }
        }
}]);

angular.module('faradayApp').
    config(['$httpProvider', function($httpProvider) {
        $httpProvider.interceptors.push('AuthInterceptor');
    }]);
