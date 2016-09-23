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
        }

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
            var daysOfMonth = new Date(selectedYear, selectedMonth, 0).getDate();
            var severities = ['unclassified','info','low','med','high','critical'];
            var vulnsDateDict = {}
            for (i in severities) {
                vulnsDateDict[severities[i]] = new Array(daysOfMonth).fill(0);
            }
            var currentMonth = new Date().getMonth();
            for (vuln in $scope.vulns.data) {
                var d = new Date(0);
                d.setUTCMilliseconds($scope.vulns.data[vuln].metadata.create_time * 1000);
                if (d.getMonth() == selectedMonth && d.getFullYear() == selectedYear) {
                    vulnsDateDict[$scope.vulns.data[vuln].severity][d.getDate() - 1]++;
                }
            }

            $scope.labels = [];
            for (i = 1; i <= daysOfMonth; i++) {
                $scope.labels.push(i.toString());
            }
            $scope.series = ['Unclassified','Info','Low','Med','High','Critical'];
            $scope.colors = ['#00ADF9','#803690','#2ecc71','#f1c40f','#e74c3c','#000000']
            $scope.data = [
                    vulnsDateDict.unclassified,
                    vulnsDateDict.info,
                    vulnsDateDict.low,
                    vulnsDateDict.med,
                    vulnsDateDict.high,
                    vulnsDateDict.critical
                ];
        }

        $scope.setMonth = function(month) {
            $scope.month = month;
            updateStackedChartData();
        }

        $scope.setYear = function(year) {
            $scope.year = year;
            updateStackedChartData();
        }

        init();
    }]);
