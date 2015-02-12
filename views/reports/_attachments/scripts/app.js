'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', ['ngRoute', 'selectionModel', 'ui.bootstrap', 'angularFileUpload', 'filter', 'ngClipboard'])
    .constant("BASEURL", (function() {
        var url = window.location.origin + "/";
        return url;
    })())
    .constant("EASEOFRESOLUTION", (function() {
        var resolutions = [
            "trivial",
            "simple",
            "moderate",
            "difficult",
            "infeasible"
        ];
        return resolutions;
    })())
    .constant("SEVERITIES", (function() {
        var severities = [
            "unclassified",
            "info",
            "low",
            "med",
            "high",
            "critical"
        ];
        return severities;
    })());

faradayApp.config(['$routeProvider', function($routeProvider) {
    $routeProvider.
        when('/dashboard/ws/:wsId', {
            templateUrl: 'scripts/dashboard/partials/dashboard.html',
            controller: 'dashboardCtrl'
        }).
        when('/dashboard', {
            templateUrl: 'scripts/partials/workspaces.html',
            controller: 'workspacesCtrl'
        }).
        when('/status/ws/:wsId', {
            templateUrl: 'scripts/partials/status_report.html',
            controller: 'statusReportCtrl'
        }).
        when('/workspaces', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl'
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