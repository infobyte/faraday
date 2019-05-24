// Faraday Penetration Test IDE
// Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('agentsCtrl', ['$scope', 'uuid',
        function ($scope, uuid) {
            $scope.newToken = null;

            $scope.init = function () {
                $scope.newToken = uuid.v4();
            };


            $scope.init();
        }]);
