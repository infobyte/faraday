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
angular.module('faradayApp')
    .controller('commonsModalEditArray', ['$scope', '$modalInstance', 'msg', function($scope, $modalInstance, msg) {
        $scope.msg = msg;
        $scope.data = {property: []};
        $scope.new_value = "";

        $scope.newValue = function() {
            if ($scope.new_value != "") {
                // we need to check if the ref already exists
                if ($scope.data.property.filter(function(ref) {return ref.value === $scope.new_value}).length == 0) {
                    $scope.data.property.push({value: $scope.new_value});
                    $scope.new_value = "";
                }
            }
        }

        $scope.ok = function() {
            // add the ref in new_ref, if there's any
            $scope.newValue();
            // convert refs to an array of strings
            var values = [];
            $scope.data.property.forEach(function(val) {
                values.push(val.value);
            });
            $scope.data.property = values;

            $modalInstance.close($scope.data.property);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss();
        }
    }]);
angular.module('faradayApp')
    .controller('commonsModalEditObject', ['$scope', '$modalInstance', 'msg', 'options', function($scope, $modalInstance, msg, options) {
        $scope.msg = msg;
        $scope.data = {property: options};

        $scope.toggleImpact = function(key) {
            $scope.data.property[key] = !$scope.data.property[key];
        };

        $scope.ok = function() {
            $modalInstance.close($scope.data.property);
        };

        $scope.cancel = function() {
            $modalInstance.dismiss();
        }
    }]);
angular.module('faradayApp')
    .controller('commonsModalEditCWE', ['$scope', '$modalInstance', 'msg', 'cweFact', function($scope, $modalInstance, msg, cweFact) {
        $scope.cweList = [];
        cweFact.get().then(function(data) {
            $scope.cweList = data;
        });
        $scope.cweLimit = 5;
        $scope.cwe_filter = "";
        $scope.msg = msg;

        $scope.data = {
            name: "",
            desc: "",
            resolution: "",
            refs: []
        };

        $scope.new_ref = "";

        $scope.populate = function(item) {
            for (var key in $scope.data) {
                if (key != "refs" && item.hasOwnProperty(key) && $scope.data.hasOwnProperty(key)) {
                    $scope.data[key] = item[key];
                }
            }
            // convert refs to an array of objects
            var refs = [];
            item.refs.forEach(function(ref) {
                refs.push({value: ref});
            });
            $scope.data.refs = refs;
        };

        $scope.ok = function() {
            if($scope.formCWE.$valid) {
                // add the ref in new_ref, if there's any
                $scope.newReference();
                // convert refs to an array of strings
                var refs = [];
                $scope.data.refs.forEach(function(ref) {
                    refs.push(ref.value);
                });
                $scope.data.refs = refs;

                $modalInstance.close($scope.data);
            }       
        };

        $scope.newReference = function() {
            if ($scope.new_ref != "") {
                // we need to check if the ref already exists
                if ($scope.data.refs.filter(function(ref) {return ref.value === $scope.new_ref}).length == 0) {
                    $scope.data.refs.push({value: $scope.new_ref});
                    $scope.new_ref = "";
                }
            }
        }

        $scope.cancel = function() {
            $modalInstance.dismiss();
        }
    }]);