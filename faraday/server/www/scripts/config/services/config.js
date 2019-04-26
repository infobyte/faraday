// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('configSrv', ['$http', 'BASEURL', function($http, BASEURL) {

        var p = $http.get(BASEURL + '_api/config')
            .then(function(conf) {
                configSrv.faraday_version = conf.data.ver;
                configSrv.show_vulns_by_price = conf.data.show_vulns_by_price;
            });

        configSrv = {
            faraday_version: null,
            promise: p,
            show_vulns_by_price: false
        }

        return configSrv;
    }]);
