// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('indexCtrl', 
        ['$scope', '$uibModal', 'indexFact',
        function($scope, $uibModal, indexFact) {
        	indexFact.getConf().then(function(conf) {
                $scope.version = conf.data.ver;

                var osint = conf.data.osint;
                osint.prefix = osint.prefix || "/search?query=";
                osint.suffix = osint.suffix || "";
                if(!osint.use_external_icon)
                    osint.icon = "images/" + osint.icon + ".png";
                $scope.osint = osint;
        	});

            $scope.about = function() {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalAbout.html',
                    scope: $scope
                });
            };

        }]);
