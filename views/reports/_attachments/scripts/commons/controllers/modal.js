// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('commonsModalDelete', ['$scope', '$modalInstance', 'msg', function($scope, $modalInstance, msg) {
        $scope.msg = msg;

        $scope.ok = function() {
            $modalInstance.close();
        };

        $scope.cancel = function() {
            $modalInstance.dismiss('cancel');
        };
    }]);

angular.module('faradayApp')
    .controller('commonsModalKoCtrl', ['$scope', '$modalInstance', 'msg', function($scope, $modalInstance, msg) {
        $scope.msg = msg;

        $scope.ok = function() {
            $modalInstance.close();
        };
    }]);

angular.module('faradayApp')
    .controller('commonsModalEditString', ['$scope', '$modalInstance', 'msg', function($scope, $modalInstance, msg) {
        $scope.msg = msg;
        $scope.data = {property: ''};

        $scope.ok = function() {
            $modalInstance.close($scope.data.property);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss();
        }
    }]);
angular.module('faradayApp')
    .controller('commonsModalEditOptions', ['$scope', '$modalInstance', 'msg', 'options', function($scope, $modalInstance, msg, options) {
        $scope.msg = msg;
        $scope.options = options;
        $scope.data = {property: ''};

        $scope.ok = function() {
            $modalInstance.close($scope.data.property);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss();
        }
    }]);