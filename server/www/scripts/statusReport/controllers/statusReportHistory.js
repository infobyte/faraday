// Faraday Penetration Test IDE
// Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('statusReportHistoryCtrl',
                    ['$scope', '$filter', '$routeParams',
                    '$location', '$uibModal', '$cookies', '$q', '$window', 'BASEURL',
                    'SEVERITIES', 'EASEOFRESOLUTION', 'hostsManager',
                    'vulnsManager', 'workspacesFact', 'csvService', 'uiGridConstants',
                    function($scope, $filter, $routeParams,
                        $location, $uibModal, $cookies, $q, $window, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, hostsManager,
                        vulnsManager, workspacesFact, csvService, uiGridConstants) {

        $scope.vulns = {}
        $scope.months = {
            0: 'January',
            1: 'February',
            2: 'March',
            3: 'April',
            4: 'May',
            5: 'June',
            6: 'July',
            7: 'August',
            8: 'September',
            9: 'October',
            10: 'November',
            11: 'December'
        };
        $scope.monthView = true;
        $scope.severities = ['unclassified','info','low','med','high','critical'];
        $scope.severitiesDisplay = {unclassified: true, info: true, low: true, med: true, high: true, critical: true};
        $scope.severitiesColors = {unclassified: '#CCCCCC', info: '#B3E6FF', low: '#2ecc71', med: '#f1c40f', high: '#e74c3c', critical: '#000000'};
        $scope.availableMonths = [];
        $scope.availableYears = [];

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
                                  null,//Mayber filter by date
                                  null,
                                  null)
            .then(function(response) {
                $scope.vulns.data = response.vulnerabilities;
                $scope.vulns.count = response.count;
                if ($scope.vulns.count > 0) {
                    updateDateSelection();
                    updateStackedChartData();
                }
            });
        };

        updateDateSelection = function() {
            for (vuln in $scope.vulns.data) {
                var d = new Date(0);
                d.setUTCMilliseconds($scope.vulns.data[vuln].metadata.create_time * 1000);
                if ($scope.availableMonths.indexOf(d.getMonth()) == -1) {
                    $scope.availableMonths.push(d.getMonth());
                    $scope.availableMonths.sort();
                }
                if ($scope.availableYears.indexOf(d.getFullYear()) == -1) {
                    $scope.availableYears.push(d.getFullYear());
                    $scope.availableYears.sort();
                }
            }
            $scope.year = $scope.availableYears.slice(-1)[0];
            $scope.month = $scope.availableMonths.slice(-1)[0];
        }
        updateStackedChartData = function() {
            var selectedYear = $scope.year;
            var selectedMonth = $scope.month;
            var monthView = $scope.monthView;
            var daysOfMonth = new Date(selectedYear, selectedMonth, 0).getDate();
            //Initializing vuln series
            var vulnsSeries = {}
            for (i in $scope.severities) {
                vulnsSeries[$scope.severities[i]] = new Array(monthView?daysOfMonth:12).fill(0);
            }

            var currentMonth = new Date().getMonth();
            for (vulnKey in $scope.vulns.data) {
                var vuln = $scope.vulns.data[vulnKey];
                var d = new Date(0);
                d.setUTCMilliseconds(vuln.metadata.create_time * 1000);
                if ((d.getMonth() == selectedMonth || !monthView) && d.getFullYear() == selectedYear && $scope.severitiesDisplay[vuln.severity]) {
                    if (monthView) {
                        vulnsSeries[vuln.severity][d.getDate() - 1]++;
                    } else {
                        vulnsSeries[vuln.severity][d.getMonth()]++;
                    }
                }
            }
            $scope.labels = [];
            if (monthView) {
                for (i = 1; i <= daysOfMonth; i++) {
                    $scope.labels.push(i.toString());
                }
            } else {
                for (monthKey in $scope.months) {
                    $scope.labels.push($scope.months[monthKey]);
                }
            }
            updateSeries();
            $scope.data = [];
            for (key in vulnsSeries) {
                if ($scope.series.indexOf(key) != -1) {
                    $scope.data.push(vulnsSeries[key])
                }
            }
        }

        updateSeries = function () {
            $scope.colors = []
            $scope.series = [];
            for (sev in $scope.severitiesDisplay) {
                if ($scope.severitiesDisplay[sev]) {
                    $scope.series.push(sev);
                    $scope.colors.push($scope.severitiesColors[sev])
                }
            }
        }

        $scope.setMonth = function(month) {
            $scope.month = month;
            updateStackedChartData();
        }

        $scope.setYear = function(year) {
            $scope.year = year;
            updateStackedChartData();
        }

        $scope.updateSeverityStatus = function(severity) {
            $scope.severitiesDisplay[severity] = !$scope.severitiesDisplay[severity];
            updateStackedChartData();
        }

        $scope.setMonthView = function() {
            $scope.monthView = true;
            updateStackedChartData();
        }

        $scope.setYearView = function() {
            $scope.monthView = false;
            updateStackedChartData();
        }

        init();
    }]);
