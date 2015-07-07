// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesModalEdit', ['$modalInstance', '$scope', 'workspace',
        function($modalInstance, $scope, workspace) {

        $scope.workspace = workspace;

        $scope.okEdit = function() {
            $modalInstance.close($scope.workspace);
        };

        $scope.cancel = function() {
            $modalInstance.close();
        };
    }]);