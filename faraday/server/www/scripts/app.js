// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

'use strict';

$.ajaxSetup({
    async: false
});

var faradayApp = angular.module('faradayApp', [
                                                    'ngRoute',
                                                    'selectionModel',
                                                    'ui.bootstrap',
                                                    'angularFileUpload',
                                                    'filter',
                                                    'angular-clipboard',
                                                    'ngCookies',
                                                    'cfp.hotkeys',
                                                    'chart.js',
                                                    'ui.grid',
                                                    'ui.grid.selection',
                                                    'ui.grid.grouping',
                                                    'ngSanitize',
                                                    'ui.grid.pagination',
                                                    'ui.grid.pinning',
                                                    'angularMoment',
                                                    'ui-notification',
                                                    'ui.grid.resizeColumns',
                                                    'angularSimplePagination',
                                                    'dndLists',
                                                    'angularFileUploadLib',
                                                    'rzTable',
                                                    'ui'
                                             ])
    .constant("BASEURL", (function() {
        if (window.location.pathname === "/"){
            var url = window.location.origin + "/";
        } else {
            var client_url_id = window.location.pathname;
            var url = window.location.origin + client_url_id;
        }
        return url;
    })())
    .constant("APIURL", (function() {
        if (window.location.pathname === "/"){
            var url = window.location.origin + "/_api/v2/";
        } else {
            var client_url_id = window.location.pathname;
            var url = window.location.origin + client_url_id + "_api/v2/";
        }
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
    })())
    .constant("EXPLOITATIONS", (function() {
        var exploitations = [
            "critical",
            "high",
            "med",
            "low",
            "info",
            "unclassified"
        ];
        return exploitations;
    })())
    .constant("SERVICE_STATUSES", (function() {
        var statuses = [
            "open",
            "closed",
            "filtered"
        ];
        return statuses;
    })())
    .constant("STATUSES", (function() {
        var statuses = [
            "opened",  // TODO migration: should we change this to "open"?
            "closed",
            "re-opened",
            "risk-accepted"
        ];
        return statuses;
    })());

faradayApp.config(['$routeProvider', '$uibTooltipProvider', 'BASEURL',
                   function($routeProvider, $uibTooltipProvider, BASEURL) {
    $uibTooltipProvider.options({
        appendToBody: true
    });
    $routeProvider.
        when('/', {
            redirectTo: "/workspaces"
        }).
        when('/dashboard/ws/:wsId', {
            templateUrl: 'scripts/dashboard/partials/dashboard.html',
            controller: 'dashboardCtrl',
            title: 'Dashboard | '
        }).
        when('/dashboard/ws', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Dashboard | '
        }).
        when('/dashboard', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Dashboard | '
        }).
        when('/extras', {
            templateUrl: 'scripts/extras/partials/extras.html',
            title: 'Extras | '
        }).
        when('/help', {
            templateUrl: 'scripts/help/partials/help.html',
            title: 'Help | '
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
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Hosts | '
        }).
        when('/host/ws/:wsId/hid/:hidId/search/:search', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Host and services | '
        }).
        when('/host/ws/:wsId/hid/:hidId/search', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Host and services | '
        }).
        when('/hosts', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Hosts | '
        }).
        when('/host/ws/:wsId/hid/:hidId', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Host and services | '
        }).
        when('/host/ws/:wsId/hid/:hidId/:edit', {
            templateUrl: 'scripts/services/partials/list.html',
            controller: 'hostCtrl',
            title: 'Host and services | '
        }).
        when('/host/ws/:wsId/new', {
            templateUrl: 'scripts/hosts/partials/new.html',
            controller: 'newHostCtrl',
            title: 'New host | '
        }).
        when('/host/ws/:wsId/', {
            redirectTo: "/hosts/ws/:wsId/"
        }).
        when('/license/lid/:lidId', {
            templateUrl: 'scripts/licenses/partials/license.html',
            controller: 'licenseCtrl',
            title: 'License | '
        }).
        when('/license', {
            templateUrl: 'scripts/licenses/partials/list.html',
            controller: 'licensesCtrl',
            title: 'Licenses | '
        }).
        when('/licenses', {
            templateUrl: 'scripts/licenses/partials/list.html',
            controller: 'licensesCtrl',
            title: 'Licenses | '
        }).
        when('/licenses/search/:search', {
            templateUrl: 'scripts/licenses/partials/list.html',
            controller: 'licensesCtrl',
            title: 'Licenses | '
        }).
        when('/licenses/search', {
            templateUrl: 'scripts/licenses/partials/list.html',
            controller: 'licensesCtrl',
            title: 'Licenses | '
        }).
        when('/status/ws/:wsId/groupby/:groupbyId', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws/:wsId/groupby/:groupbyId/search/:search', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws/:wsId/groupby/:groupbyId/search', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws/:wsId/search/:search*\/', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws/:wsId/search', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws/:wsId', {
            templateUrl: 'scripts/statusReport/partials/statusReport.html',
            controller: 'statusReportCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status/ws', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Status Report | ',
            resolve: {
                workspaceData: function($route, workspacesFact){
                    return workspacesFact.get($route.current.params.wsId);
                }
            }
        }).
        when('/status', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Status Report | '
        }).
        when('/workspaces', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Workspaces | '
        }).
        when('/comparison', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl'
        }).
        when('/webshell', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl'
        }).
        when('/executive', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl',
            title: 'Executive Report | '
        }).
        when('/workflows', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl',
            title: 'Workflows | '
        }).
        when('/scheduling', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl',
            title: 'Scheduling | '
        }).
        when('/login', {
            templateUrl: 'scripts/auth/partials/login.html',
            controller: 'loginCtrl',
            title: 'Login | '
        }).
        when('/users', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl',
            title: 'Users | '
        }).
        when('/credentials', {
            templateUrl: 'scripts/credentials/partials/list.html',
            controller: 'credentialsCtrl',
            title: 'Credentials | '
        }).
        when('/credentials/ws', {
            templateUrl: 'scripts/workspaces/partials/list.html',
            controller: 'workspacesCtrl',
            title: 'Credentials | '
        }).
        when('/credentials/ws/:wsId', {
            templateUrl: 'scripts/credentials/partials/list.html',
            controller: 'credentialsCtrl',
            title: 'Credentials | '
        }).
        when('/credentials/ws/:wsId/hid/:hId', {
            templateUrl: 'scripts/credentials/partials/list.html',
            controller: 'credentialsCtrl',
            title: 'Credentials | '
        }).
        when('/credentials/ws/:wsId/sid/:sId', {
            templateUrl: 'scripts/credentials/partials/list.html',
            controller: 'credentialsCtrl',
            title: 'Credentials | '
        }).
        when('/vulndb', {
            templateUrl: 'scripts/vulndb/partials/vulndb.html',
            controller: 'vulnModelsCtrl',
            title: 'Vulnerabilities | '
        }).
        when('/data_analysis', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl'
        }).
        when('/taskgroup', {
            templateUrl: 'scripts/commons/partials/commercial.html',
            controller: 'commercialCtrl',
            title: 'Methodologies | '
        }).
        when('/forbidden', {
            templateUrl: 'scripts/auth/partials/forbidden.html',
            title: ' Forbidden | '
        }).
        when('/workspace-worth/ws/:wsId', {
            templateUrl: 'scripts/dashboard/partials/vulns-by-price.html',
            controller: 'vulnsByPriceCtrl',
            title: ' Workspace worth | '
        }).
        when('/admin', {
            templateUrl: 'scripts/admin/admin.html',
            controller: 'adminCtrl',
            title: ' Admin | '
        }).
        when('/admin/:item', {
            templateUrl: 'scripts/admin/admin.html',
            controller: 'adminCtrl',
            title: ' Admin | '
        }).
        otherwise({redirectTo:'/'});
}]);

faradayApp.run(['$location', '$rootScope', 'loginSrv', function($location, $rootScope, loginSrv) {
    $rootScope.$on('$routeChangeSuccess', function(event, current, previous) {
        if(current.hasOwnProperty('$$route')) {
            $rootScope.title = current.$$route.title;
        }
    });
}]);
