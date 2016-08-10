// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('indexFact', ['$http', function($http) {
        var indexFact = {};

        indexFact.getConf = function() {
        	return $http.get('config/config.json');
        };

        return indexFact;
    }]);