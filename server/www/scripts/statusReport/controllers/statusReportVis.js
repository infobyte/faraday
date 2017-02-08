// Faraday Penetration Test IDE
// Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('statusReportVisCtrl',
                    ['$scope', '$filter', '$routeParams',
                    '$location', '$uibModal', '$cookies', '$q', '$window', 'BASEURL',
                    'SEVERITIES', 'EASEOFRESOLUTION', 'hostsManager',
                    'vulnsManager', 'workspacesFact', 'csvService', 'uiGridConstants',
                    function($scope, $filter, $routeParams,
                        $location, $uibModal, $cookies, $q, $window, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, hostsManager,
                        vulnsManager, workspacesFact, csvService, uiGridConstants) {

        const RADAR_DISPLAY_TARGET = 'Target'
        const RADAR_DISPLAY_HOST = 'Host'

        $scope.vulns = {}
        $scope.severities = ['unclassified','info','low','med','high','critical'];
        $scope.severitiesDisplay = {unclassified: true, info: true, low: true, med: true, high: true, critical: true};
        $scope.severitiesColors = {unclassified: '#CCCCCC', info: '#B3E6FF', low: '#2ecc71', med: '#f1c40f', high: '#e74c3c', critical: '#000000'};

        $scope.radarChartLabels = $scope.severities;
        $scope.radarChartDisplay = RADAR_DISPLAY_HOST;

        init = function() {
            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            // current workspace
            $scope.workspace = $routeParams.wsId;

            loadVulns();
        }  

        loadVulns = function() {
            // load all vulnerabilities
            vulnsManager.getVulns($scope.workspace,
                                  null,
                                  null,
                                  null,
                                  null,
                                  null)
            .then(function(response) {
                $scope.vulns.data = response.vulnerabilities;
                $scope.vulns.count = response.count;
                if ($scope.vulns.count > 0) {
                    updateRadarData();
                }
            });
        };

        
        updateRadarData = function() {
            $scope.radarChartSeries = []
            $scope.radarChartData = []
            switch($scope.radarChartDisplay) {
                case RADAR_DISPLAY_TARGET:
                    let targets = {}
                    $scope.vulns.data.forEach(vuln => {
                        if (!targets[vuln.target]) {
                            targets[vuln.target] = new Array($scope.severities.length).fill(0);
                        }
                        targets[vuln.target][$scope.severities.indexOf(vuln.severity)]++;
                    });
                    Object.keys(targets).forEach(key => {
                        $scope.radarChartSeries.push(key);
                        $scope.radarChartData.push(targets[key]);
                    })
                    break;
                case RADAR_DISPLAY_HOST:
                    let hosts = {};
                    $scope.vulns.data.forEach(vuln => {
                        if (Array.isArray(vuln.hostnames)) {
                            vuln.hostnames.forEach(host => {
                                if (!hosts[host]) {
                                    hosts[host] = new Array($scope.severities.length).fill(0);
                                }
                                hosts[host][$scope.severities.indexOf(vuln.severity)]++;
                            })
                        }
                    });
                    Object.keys(hosts).forEach(key => {
                        $scope.radarChartSeries.push(key);
                        $scope.radarChartData.push(hosts[key]);
                    })
                    break;
                default:
                    throw "Display not implemented"
            }
        }

        $scope.switchToTargetDisplay = function() {
            $scope.radarChartDisplay = RADAR_DISPLAY_TARGET;
            updateRadarData();
        }

        $scope.switchToHostDisplay = function() {
            $scope.radarChartDisplay = RADAR_DISPLAY_HOST;
            updateRadarData();
        }

        init();
    }]);
