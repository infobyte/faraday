// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp').directive('appendSearchParam', ['$routeParams', '$location', function ($routeParams, $location) {
    return {
        restrict: 'A',
        replace: false,
        link: function (scope, element, attr) {

            element.on('click', function (event) {
                scope.currentParams = $routeParams.search;
                if (scope.currentParams !== undefined) {
                    scope.newParam = attr.appendSearchParam;
                    var hash = window.location.hash;
                    var basePath = hash.slice(1, hash.indexOf("search") + 7);
                    if (scope.newParam.indexOf('%2520') !== -1){
                        scope.newParam = decodeURIComponent(scope.newParam);
                    }

                    scope.fullPath = basePath + scope.currentParams + '&' + scope.newParam;
                    if (paramAlreadyExists(scope.currentParams, scope.newParam)) {
                        scope.fullPath = basePath + scope.currentParams;
                    }

                    event.preventDefault();
                    $location.path(scope.fullPath);
                }
            });

            var paramAlreadyExists = function (currentParam, newParam) {
                var currentParamStr = decodeURIComponent(decodeURIComponent(currentParam));
                var newParamStr = decodeURIComponent(decodeURIComponent(newParam));
                return currentParamStr === newParamStr || currentParamStr.indexOf(newParamStr) !== -1;
            }
        }
    };
}]);