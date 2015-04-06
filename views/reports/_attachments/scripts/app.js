// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', ['ngRoute', 'selectionModel', 'ui.bootstrap', 'angularFileUpload', 'filter', 'ngClipboard', 'ngCookies'])
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
            controller: 'dashboardCtrl',
            title: 'Dashboard'
        }).
        when('/dashboard', {
            templateUrl: 'scripts/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Dashboard'
        }).
        when('/status/ws/:wsId', {
            templateUrl: 'scripts/partials/status_report.html',
            controller: 'statusReportCtrl',
            title: 'Status Report'
        }).
        when('/workspaces', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Workspaces'
        }).
        when('/status', {
            templateUrl: 'scripts/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Status Report'
        }).
        otherwise({
            templateUrl: 'scripts/partials/home.html',
            controller: 'statusReportCtrl',
            title: 'Web UI'
        });
}]);

faradayApp.run(['$location', '$rootScope', function($location, $rootScope) {
    $rootScope.$on('$routeChangeSuccess', function(event, current, previous) {
        $rootScope.title = current.$$route.title;
    });
}]);
