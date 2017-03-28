// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', 'indexFact',
        function($scope, indexFact) {
        	indexFact.getConf().then(function(conf) {
                    var osint = conf.data.osint;
                    osint.prefix = osint.prefix || "/search?query=";
                    osint.suffix = osint.suffix || "";
                    if(!osint.use_external_icon)
                        osint.icon = "images/" + osint.icon + ".png";
                    $scope.osint = osint;
        	});

        }]);
