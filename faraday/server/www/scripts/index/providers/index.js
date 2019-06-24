// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('indexFact', ['$http', 'BASEURL', function($http, BASEURL) {
        var indexFact = {};

        indexFact.getConf = function() {
        	return $http.get(BASEURL + '_api/config');
        };

        return indexFact;
    }]);
