// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .service('loginSrv', ['BASEURL', '$q', '$cookies', function(BASEURL, $q, $cookies) {

        loginSrv = {
            is_authenticated: false,
            user_obj: null,
            last_time_checked: new Date(0),

            login: function(user, pass, remember){
                var deferred = $q.defer();
                $.ajax({
                    type: 'POST',
                    url: BASEURL + '_api/login',
                    data: JSON.stringify({"email": user, "password": pass, "remember": remember}),
                    dataType: 'json',
                    contentType: 'application/json'
                })
                .done(function(){
                    $.getJSON(BASEURL + '_api/session', function(data) {
                        loginSrv.user_obj = data;
                        loginSrv.last_time_checked = new Date();
                        loginSrv.is_authenticated = true;
                        deferred.resolve(loginSrv.user_obj);
                    });
                })
                .fail(function(){
                    loginSrv.is_authenticated = false;
                    loginSrv.user_obj = null;
                    deferred.reject();
                });
                return deferred.promise;
            },

            _check: function(deferred) {
                $.getJSON(BASEURL + '_api/session', function(data) {
                    loginSrv.user_obj = data;
                    loginSrv.is_authenticated = true;
                    loginSrv.last_time_checked = new Date();
                    deferred.resolve(loginSrv.is_authenticated);
                }).fail(function(){
                    loginSrv.user_obj = null;
                    loginSrv.is_authenticated = false;
                    loginSrv.last_time_checked = new Date();
                    deferred.resolve(loginSrv.is_authenticated);
                });
            },

            isAuthenticated: function(){
                var deferred = $q.defer();
                var seconds = (new Date() - loginSrv.last_time_checked) / 1000;
                if (seconds > 1){
                    //more than one second since checked for last time
                    loginSrv._check(deferred);
                } else {
                    deferred.resolve(loginSrv.is_authenticated);
                }
                return deferred.promise;
            },

            isAuth: function(){
                return loginSrv.is_authenticated;
            },

            getUser: function(){
                var deferred = $q.defer();
                $.getJSON(BASEURL + '_api/session', function(data) {
                    loginSrv.user_obj = data;
                    deferred.resolve(loginSrv.user_obj);
                })
                .fail(function(){
                    deferred.reject();
                });
                return deferred.promise;
            },

            logout: function(){
                var deferred = $q.defer();
                var callback = function(){
                    loginSrv.is_authenticated = false;
                    loginSrv.user_obj = null;
                    deferred.resolve();
                }
                $cookies.remove('remember_token');
                $.ajax({
                    url: BASEURL + '_api/logout',
                    type: 'GET',
                    success: callback,
                    error: callback
                });
                return deferred.promise;
            },

            recover: function(email){
                var deferred = $q.defer();

                $.ajax({
                    type: 'POST',
                    url: BASEURL + '_api/auth/forgot_password',
                    data: JSON.stringify({"email": email}),
                    dataType: 'json',
                    contentType: 'application/json'
                })
                .done(function(data){
                    deferred.resolve(data);
                })
                .fail(function(){
                    deferred.reject();
                });

                return deferred.promise;
            }
        }

        loginSrv.isAuthenticated();

        return loginSrv;
    }]);
