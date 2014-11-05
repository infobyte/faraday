'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', ['ngRoute', 'selectionModel', 'ui.bootstrap'])
    .constant("BASEURL", (function() {
        var url = window.location.origin + "/";
        return url;
    })());

faradayApp.config(['$routeProvider', function($routeProvider) {
    $routeProvider.
        when('/ws/:wsId', {
            templateUrl: 'scripts/partials/status_report.html',
            controller: 'statusReportCtrl'
        }).
        when('/', {
            templateUrl: 'scripts/partials/workspaces.html',
            controller: 'workspacesCtrl'
        }).
        otherwise({
            templateUrl: 'scripts/partials/status_report.html',
            controller: 'statusReportCtrl'
        });
}]);
