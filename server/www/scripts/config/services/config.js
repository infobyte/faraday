// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('configSrv', ['BASEURL', '$http', function(BASEURL, $http) {

        var p = $http.get('config/config.json')
            .then(function(conf) {
                configSrv.faraday_version = conf.data.ver;
                configSrv.license_db = conf.data.lic_db;
                configSrv.vulnModelsDB = conf.data.vuln_model_db
            });

        configSrv = {
            faraday_version: null,
            license_db: null,
            promise: p
        }

        return configSrv;
    }]);
