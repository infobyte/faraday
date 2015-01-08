'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', ['ngRoute', 'selectionModel', 'ui.bootstrap', 'angularFileUpload'])
    .constant("BASEURL", (function() {
        var url = window.location.origin + "/";
        return url;
    })());

faradayApp.config(['$routeProvider', function($routeProvider) {
    $routeProvider.
        when('/status/ws/:wsId', {
            templateUrl: 'scripts/partials/status_report.html',
            controller: 'statusReportCtrl'
        }).
        when('/status', {
            templateUrl: 'scripts/partials/workspaces.html',
            controller: 'workspacesCtrl'
        }).
        otherwise({
            templateUrl: 'scripts/partials/home.html',
            controller: 'statusReportCtrl'
        });
}]);
