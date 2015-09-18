// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', ['ngRoute', 'selectionModel', 'ui.bootstrap', 'angularFileUpload', 'filter', 'ngClipboard', 'ngCookies', 'cfp.hotkeys', 'chart.js'])
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
            "critical",
            "high",
            "med",
            "low",
            "info",
            "unclassified"
        ];
        return severities;
    })());

faradayApp.config(['$routeProvider', 'ngClipProvider', function($routeProvider, ngClipProvider) {
    ngClipProvider.setPath("script/ZeroClipboard.swf");
    $routeProvider.
        when('/dashboard/ws/:wsId', {
            templateUrl: 'scripts/dashboard/partials/dashboard.html',
            controller: 'dashboardCtrl',
            title: 'Dashboard | '
        }).
        when('/dashboard/ws', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Dashboard | '
        }).
        when('/dashboard', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Dashboard | '
        }).
        when('/hosts/ws/:wsId/search/:search', {
            templateUrl: 'scripts/hosts/partials/list.html',
            controller: 'hostsCtrl',
            title: 'Hosts | '
        }).
        when('/hosts/ws/:wsId/search', {
            templateUrl: 'scripts/hosts/partials/list.html',
            controller: 'hostsCtrl',
            title: 'Hosts | '
        }).
        when('/hosts/ws/:wsId', {
            templateUrl: 'scripts/hosts/partials/list.html',
            controller: 'hostsCtrl',
            title: 'Hosts | '
        }).
        when('/hosts/ws', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Hosts | '
        }).
        when('/host/ws/:wsId/hid/:hidId/search/:search', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Services | '
        }).
        when('/host/ws/:wsId/hid/:hidId/search', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Services | '
        }).
        when('/hosts', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Hosts | '
        }).
        when('/host/ws/:wsId/hid/:hidId', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Services | '
        }).
        when('/status/ws/:wsId/search/:search', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | '
        }).
        when('/status/ws/:wsId/search', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | '
        }).
        when('/status/ws/:wsId', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | '
        }).
        when('/status/ws', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Status Report | '
        }).
        when('/status', {
            templateUrl: 'scripts/commons/partials/workspaces.html',
            controller: 'workspacesCtrl',
            title: 'Status Report | '
        }).
        when('/workspaces', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Workspaces | '
        }).
        otherwise({
            templateUrl: 'scripts/commons/partials/home.html',
            controller: 'statusReportCtrl'
        });
}]);

faradayApp.run(['$location', '$rootScope', function($location, $rootScope) {
    $rootScope.$on('$routeChangeSuccess', function(event, current, previous) {
        if(current.hasOwnProperty('$$route')) {
            $rootScope.title = current.$$route.title;
        }
    });
}]);
