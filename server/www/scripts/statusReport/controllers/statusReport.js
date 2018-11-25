// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module("faradayApp")
    .controller("statusReportCtrl",
                    ["$scope", "$filter", "$routeParams",
                     "$location", "$uibModal", "$cookies", "$q", "$window", "BASEURL",
                     "SEVERITIES", "EASEOFRESOLUTION", "STATUSES", "hostsManager", "commonsFact",
                     "vulnsManager", "workspacesFact", "csvService", "uiGridConstants", "vulnModelsManager",
                     "referenceFact", "ServerAPI", '$http',
                    function($scope, $filter, $routeParams,
                        $location, $uibModal, $cookies, $q, $window, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, STATUSES, hostsManager, commonsFact,
                        vulnsManager, workspacesFact, csvService, uiGridConstants, vulnModelsManager, referenceFact, ServerAPI, $http) {
        $scope.baseurl;
        $scope.columns;
        $scope.columnsWidths;
        $scope.easeofresolution;
        $scope.interfaces;
        $scope.reverse;
        $scope.severities;
        $scope.search;
        $scope.searchParams;
        $scope.sortField;
        $scope.vulns;
        $scope.workspaces;
        $scope.currentPage;
        $scope.gridOptions;
        $scope.vulnModelsManager;

        $scope.vulnWebSelected;

        $scope.gridHeight;
        var allVulns;

        var searchFilter = {};
        var paginationOptions = {
            page: 1,
            pageSize: 100,
            defaultPageSizes: [10, 50, 75, 100],
            sortColumn: null,
            sortDirection: null
        };

        var init = function() {
            $scope.baseurl = BASEURL;
            $scope.severities = SEVERITIES;
            $scope.easeofresolution = EASEOFRESOLUTION;
            $scope.propertyGroupBy = $routeParams.groupbyId;
            $scope.sortField = "date";
            $scope.reverse = true;
            $scope.vulns = [];
            $scope.selected = false;
            $scope.vulnModelsManager = vulnModelsManager;
            $scope.loading = true;
            $scope.gridOptions = {
                multiSelect: true,
                enableSelectAll: true,
                enableColumnMenus: false,
                enableRowSelection: true,
                enableRowHeaderSelection: false,
                useExternalPagination: true,
                useExternalSorting: true,
                paginationPageSizes: paginationOptions.defaultPageSizes,
                paginationPageSize: paginationOptions.pageSize,
                enableHorizontalScrollbar: 0,
                treeRowHeaderAlwaysVisible: false,
                enableGroupHeaderSelection: true,
                rowHeight: 47
            };
            $scope.gridOptions.columnDefs = [];

            var storedPageSize = parseInt($cookies.get("pageSize"));
            if ( storedPageSize && storedPageSize > 0 ) {
                paginationOptions.pageSize = storedPageSize;
                $scope.gridOptions.paginationPageSize = storedPageSize;
            }

            if($cookies.get("filterConfirmed") !== undefined) {
                $scope.propertyFilterConfirmed = $cookies.get("filterConfirmed");
            }else{
                $scope.propertyFilterConfirmed = "All";
            }

            $scope.gridOptions.onRegisterApi = function(gridApi){
                //set gridApi on scope
                $scope.gridApi = gridApi;

                $scope.gridApi.selection.on.rowSelectionChanged( $scope, function ( rowChanged ) {
                    $scope.selectionChange();
                    if ( typeof(rowChanged.treeLevel) !== "undefined" && rowChanged.treeLevel > -1 ) {
                        // this is a group header
                        children = $scope.gridApi.treeBase.getRowChildren( rowChanged );
                        children.forEach( function ( child ) {
                            if ( rowChanged.isSelected ) {
                                $scope.gridApi.selection.selectRow( child.entity );
                            } else {
                                $scope.gridApi.selection.unSelectRow( child.entity );
                            }
                        });
                    }
                });

                $scope.gridApi.pagination.on.paginationChanged($scope, function (pageNumber, pageSize) {
                    // Save new page size in cookie
                    $cookies.put("pageSize", pageSize);

                    // Clear selection
                    $scope.gridApi.selection.clearSelectedRows();

                    paginationOptions.page = pageNumber;
                    paginationOptions.pageSize = pageSize;

                    // Load new page
                    loadVulns();
                });

                $scope.gridApi.core.on.sortChanged($scope, function(grid, sortColumns) {
                    if (sortColumns.length === 0) {
                        sortRowsBy(null, null);
                    } else {
                        sortRowsBy(sortColumns[0].name, sortColumns[0].sort.direction);
                    }
                    loadVulns();
                });

                $scope.gridApi.core.on.rowsRendered($scope, function() {
                    resizeGrid();
                    recalculateLastVisibleColSize();
                });

                $scope.gridApi.colResizable.on.columnSizeChanged($scope, function (colDef, deltaChange) {
                    for (i = 0; i < $scope.gridApi.grid.columns.length; i++) {
                        if ($scope.gridApi.grid.columns[i].name === colDef.name) {
                            var newWidth = $scope.gridApi.grid.columns[i].width;
                            $scope.columnsWidths[colDef.name] = newWidth;
                            $cookies.put("SRcolWidth", JSON.stringify($scope.columnsWidths));
                            recalculateLastVisibleColSize();
                            break;
                        }
                    }
                });
            };

            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            // current workspace
            $scope.workspace = $routeParams.wsId;

            // load current workspace data
            workspacesFact.get($scope.workspace).then(function(response) {
                $scope.workspaceData = response;
            });

            $scope.interfaces = [];
            // current search
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            if($scope.propertyFilterConfirmed === "Confirmed") {
                if($scope.search !== undefined) {
                    $scope.search = $scope.search.concat("&confirmed=true");
                } else {
                    $scope.search = "confirmed=true";
                }
            }

            if($scope.propertyFilterConfirmed === "Unconfirmed") {
                if($scope.search !== undefined) {
                    $scope.search = $scope.search.concat("&confirmed=false");
                } else {
                    $scope.search = "confirmed=false";
                }
            }


            $scope.hash = window.location.hash;
            if(window.location.hash.substring(1).indexOf("search") !== -1) {
                $scope.hash = $scope.hash.slice(0, window.location.hash.indexOf("search") - 1);
            }

            if($scope.search !== "" && $scope.search !== undefined && $scope.search.indexOf("=") > -1) {
                searchFilter = commonsFact.parseSearchURL($scope.search);
                $scope.searchParams = commonsFact.searchFilterToExpression(searchFilter);
            }

            $scope.columns = {
                "_id":               true,
                "date":             true,
                "name":             true,
                "severity":         true,
                "service":          true,
                "target":           true,
                "host_os":          false,
                "desc":             true,
                "resolution":       false,
                "data":             false,
                "easeofresolution": false,
                "status":           true,
                "website":          false,
                "path":             false,
                "request":          false,
                "refs":             false,
                "evidence":         false,
                "hostnames":        true,
                "impact":           false,
                "method":           false,
                "params":           false,
                "pname":            false,
                "query":            false,
                "response":         false,
                "web":              false,
                "creator":          false,
                "policyviolations":  false
            };


            if (typeof ($cookies.get("SRcolWidth")) !== "undefined") {
                $scope.columnsWidths = JSON.parse($cookies.get("SRcolWidth"));
            }
            else {
                $scope.columnsWidths = {
                    "name":             "120",
                    "service":          "110",
                    "hostnames":        "130",
                    "target":           "100",
                    "host_os":          "300",
                    "desc":             "600",
                    "resolution":       "170",
                    "data":             "170",
                    "easeofresolution": "140",
                    "status":           "100",
                    "website":          "90",
                    "path":             "90",
                    "request":          "90",
                    "refs":             "20",
                    "_attachments":     "100",
                    "impact":           "90",
                    "method":           "90",
                    "params":           "90",
                    "pname":            "90",
                    "query":            "100",
                    "response":         "90",
                    "web":              "80",
                    "metadata.creator": "100",
                    "policyviolations": "100"
                };
            }

            // created object for columns cookie columns
            if(typeof($cookies.get("SRcolumns")) !== "undefined"){
                var arrayOfColumns = $cookies.get("SRcolumns").replace(/[{}"']/g, "").split(',');
                arrayOfColumns.forEach(function(column){
                    var columnFinished = column.split(":");
                    if ($scope.columns.hasOwnProperty(columnFinished[0])) {
                        $scope.columns[columnFinished[0]] = columnFinished[1] === "true" ? true: false;
                    }
                });
            }

            // load cookie of columns ordering if exists
            paginationOptions.sortColumn = $cookies.get("SRsortColumn") || null;
            paginationOptions.sortDirection = $cookies.get("SRsortDirection") || null;

            defineColumns();

            $scope.vulnWebSelected = false;

            groupByColumn();

            loadVulns();

            angular.element($window).bind("resize", function () {
                resizeGrid();
            });
        };

        var defineColumns = function() {
            $scope.gridOptions.columnDefs.push({ name: "confirmVuln", width: "45", enableColumnResizing: false, headerCellTemplate:  "<i class=\"fa fa-check cursor\" ng-click=\"grid.appScope.selectAll()\" ng-style=\"{'opacity':(grid.appScope.selected === true) ? '1':'0.6'}\"></i>", cellTemplate: "scripts/statusReport/partials/ui-grid/confirmbutton.html" });

            function getColumnSort(columnName){
                if($cookies.get("SRsortColumn") === columnName){
                    direction = ($cookies.get("SRsortDirection").toLowerCase() == "asc")
                                 ? uiGridConstants.ASC
                                 : uiGridConstants.DESC;
                    return {ignoreSort: true, priority: 0, direction: direction};
                }else{
                    return {};
                }
            }

            var header = '<div ng-class="{ \'sortable\': sortable }">'+
                    '       <div class="ui-grid-cell-contents" col-index="renderIndex" title="TOOLTIP">{{ col.displayName CUSTOM_FILTERS }}'+
                    '           <a href="" ng-click="grid.appScope.toggleShow(col.displayName, true)">'+
                    '               <span class="glyphicon glyphicon-remove"></span>'+
                    '           </a>'+
                    '           <span ui-grid-visible="col.sort.direction" ng-class="{ \'ui-grid-icon-up-dir\': col.sort.direction == asc, \'ui-grid-icon-down-dir\': col.sort.direction == desc, \'ui-grid-icon-blank\': !col.sort.direction }">&nbsp;</span>'+
                    '       </div>'+
                    '       <div class="ui-grid-column-menu-button" ng-if="grid.options.enableColumnMenus && !col.isRowHeader  && col.colDef.enableColumnMenu !== false" ng-click="toggleMenu($event)" ng-class="{\'ui-grid-column-menu-button-last-col\': isLastCol}">'+
                    '           <i class="ui-grid-icon-angle-down">&nbsp;</i>'+
                    '       </div>'+
                    '       <div ui-grid-filter></div>'+
                    '   </div>';

            $scope.gridOptions.columnDefs.push({ name : 'severity',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/severitycolumn.html',
                headerCellTemplate: header,
                displayName : "sev",
                type: 'string',
                visible: $scope.columns["severity"],
                sort: getColumnSort('severity'),
                sortingAlgorithm: compareSeverities,
                maxWidth: 50,
                minWidth: 50,
            });
            $scope.gridOptions.columnDefs.push({ name : 'name',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/namecolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('name'),
                visible: $scope.columns["name"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'service',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/servicecolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["service"],
                field: "service.summary",
                displayName : "service",
                sort: getColumnSort('service'),
            });
             $scope.gridOptions.columnDefs.push({ name : 'hostnames',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/hostnamescolumn.html',
                headerCellTemplate: header,
                minWidth: '100',
                maxWidth: '200',
                enableSorting: false,
                sort: getColumnSort('hostnames'),
                visible: $scope.columns["hostnames"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'target',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/targetcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('target'),
                visible: $scope.columns["target"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'host_os',
                displayName: "host_os", // Don't touch this! It will break everything. Seriously
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/hostoscolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('host_os'),
                visible: $scope.columns["host_os"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'desc',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/desccolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('desc'),
                visible: $scope.columns["desc"],
                minWidth: '300',
                maxWidth: '600',
            });
            $scope.gridOptions.columnDefs.push({ name : 'resolution',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('resolution'),
                visible: $scope.columns["resolution"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'data',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('data'),
                visible: $scope.columns["data"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'easeofresolution',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                minWidth: '150',
                sort: getColumnSort('easeofresolution'),
                visible: $scope.columns["easeofresolution"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'website',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('website'),
                visible: $scope.columns["website"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'path',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('path'),
                visible: $scope.columns["path"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'request',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('request'),
                visible: $scope.columns["request"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'refs',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/refscolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('refs'),
                visible: $scope.columns["refs"],
                enableSorting: false,
            });
            $scope.gridOptions.columnDefs.push({ name : '_attachments',
                displayName: "evidence",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/evidencecolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('_attachments'),
                visible: $scope.columns["evidence"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'impact',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/impactcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('impact'),
                enableSorting: false,
                visible: $scope.columns["impact"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'method',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('method'),
                visible: $scope.columns["method"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'params',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('params'),
                visible: $scope.columns["params"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'pname',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('pname'),
                visible: $scope.columns["pname"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'query',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('query'),
                visible: $scope.columns["query"],
            });
            $scope.gridOptions.columnDefs.push({ name : 'response',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('response'),
                visible: $scope.columns["response"],
                width: $scope.columnsWidths['response'],
            });
            $scope.gridOptions.columnDefs.push({ name : 'web',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/webcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('web'),
                visible: $scope.columns["web"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'metadata.creator',
                displayName : "creator",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/creatorcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('metadata.creator'),
                visible: $scope.columns["creator"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'policyviolations',
                // The following line breaks the remembering of the field (i.e.
                // setting it in the SRcolumns cookie), so it is better to
                // leave it commented (or to debug the problem, which I don't
                // want to)
                // displayName : "policy violations",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/policyviolationscolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('policyviolations'),
                visible: $scope.columns["policyviolations"],
                enableSorting: false,
            });

            $scope.gridOptions.columnDefs.push({ name : '_id',
                displayName : "id",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/idcolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('_id'),
                visible: $scope.columns["_id"],
                maxWidth: 60,
            });
            $scope.gridOptions.columnDefs.push({ name : 'date',
                displayName : "date",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/datecolumn.html',
                headerCellTemplate: header,
                sort: getColumnSort('date'),
                visible: $scope.columns["date"],
                maxWidth: 100,
                minWidth: 100,
            });
            $scope.gridOptions.columnDefs.push({ name : 'status',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/statuscolumn.html',
                headerCellTemplate: header,
                field: "status",
                sort: getColumnSort('status'),
                visible: $scope.columns["status"],
                maxWidth: 90,
                minWidth: 90,
            });
        };


        var groupByColumn = function() {
            for (var i = 0; i < $scope.gridOptions.columnDefs.length; i++) {
                var column = $scope.gridOptions.columnDefs[i];
                var colname = column.displayName !== undefined ? column.displayName : column.name;
                if ( colname == $scope.propertyGroupBy && $scope.columns[colname] == true) {
                    column.grouping = { groupPriority: 0 };
                    paginationOptions.sortColumn = colname;
                    paginationOptions.sortDirection = 'asc';
                }else if (colname === 'sev' && $scope.propertyGroupBy === 'severity'){
                    // Ugly ugly hack so I don't have to change the displayName of
                    // severity from "sev" to "severity"
                    column.grouping = { groupPriority: 0 };
                    paginationOptions.sortColumn = 'severity';
                    paginationOptions.sortDirection = 'asc'
                }
            }
        };

        var sortRowsBy = function(columnName, sortDirection) {
            paginationOptions.sortColumn = columnName;
            paginationOptions.sortDirection = sortDirection;
            $cookies.put('SRsortColumn', columnName || '');
            $cookies.put('SRsortDirection', sortDirection || '');
        }

        $scope.confirmedTooltip = function(isConfirmed) {
            if(!$scope.workspaceData.active){
                return 'Read-only. Workspace disabled';
            }

            if(isConfirmed === true) {
                return "Change to false positive";
            } else {
                return "Confirm";
            }
        };

        $scope.searchExploits = function(){

            var promises = [];
            var selected = $scope.getCurrentSelection();

            selected.forEach(function(vuln){

                vuln.refs.forEach(function(ref){

                    if(ref.toLowerCase().startsWith('cve')){

                        var response = ServerAPI.getExploits(ref);
                        promises.push(response);
                    }
                });
            });

            return $q.all(promises).then(function(modalData){

                var response = modalData.map(function(obj){
                    return obj.data;
                });

                return response.filter(function(x){
                  return !angular.equals(x["exploitdb"], []) && !angular.equals(x["metasploit"], [])
                });

            }, function(failed) {
                commonsFact.showMessage("Something failed searching vulnerability exploits.");
                return [];
            });
        }

        $scope.showExploits = function(){

           $scope.searchExploits().then(function(exploits){

                if(exploits.length > 0){

                    var modal = $uibModal.open({
                        templateUrl: 'scripts/statusReport/partials/exploitsModal.html',
                        controller: 'commonsModalExploitsCtrl',
                        resolve: {
                            msg: function() {
                                return exploits;
                            }
                        }
                    });
                }
            });
        }
        var resizeGrid = function() {
            $scope.gridHeight = getGridHeight('grid', 'right-main', 15);
        };

        var recalculateLastVisibleColSize = function () {
            var lastFound = false;
            for (i = $scope.gridApi.grid.columns.length - 1; i >= 0; i--) {
                if ($scope.gridApi.grid.columns[i].visible) {
                    if (!lastFound) {
                        $scope.gridApi.grid.columns[i].width = "*";
                        lastFound = true
                    } else if ($scope.gridApi.grid.columns[i].width === "*" && $scope.columnsWidths[$scope.gridApi.grid.columns[i].name] != undefined) {
                        $scope.gridApi.grid.columns[i].width = parseInt($scope.columnsWidths[$scope.gridApi.grid.columns[i].name]);
                    }
                }
            }
        };

        var getGridHeight = function(gridClass, contentClass, bottomOffset) {
            var contentOffset = angular.element(document.getElementsByClassName(contentClass)[0]).offset();
            var contentHeight = angular.element(document.getElementsByClassName(contentClass)[0]).height();
            var gridOffset = angular.element(document.getElementsByClassName(gridClass)).offset();
            if (gridOffset !== undefined) {
                var gridHeight = contentHeight - (gridOffset.top) - bottomOffset;
                return gridHeight + 'px';
            }
        };

        $scope.saveAsModel = function() {
            var self = this;
            var selected = $scope.getCurrentSelection();
            var promises = [];
            try {
                selected.forEach(function(vuln) {
                    vuln.exploitation = vuln.severity;
                    vuln.description = vuln.desc;
                    vuln.desc_summary = vuln.desc;
                    vuln.references = vuln.refs;
                    promises.push(self.vulnModelsManager.create(vuln, true));
                });
                $q.all(promises).then(function(success) {
                    commonsFact.showMessage("Created " + selected.length + " templates successfully.", true);
                }, function(failedMessage) {
                    commonsFact.showMessage(failedMessage);
                });
            } catch(err) {
                commonsFact.showMessage("Something failed when creating some of the templates.");
            }
        };

        $scope.selectAll = function() {
            if($scope.selected === false) {
                for(var i = 0; i <= $scope.gridOptions.paginationPageSize; i++) {
                    $scope.gridApi.selection.selectRowByVisibleIndex(i);
                }
                $scope.selected = true;
            } else {
                $scope.gridApi.selection.clearSelectedRows();
                var allVisibleRows = $scope.gridApi.core.getVisibleRows($scope.gridApi);
                allVisibleRows.forEach(function(row) {
                    if(row.groupHeader === true && row.isSelected === true) {
                        row.isSelected = false;
                    }
                });
                $scope.selected = false;
            }
        };

        $scope.processReference = function(text) {
            return referenceFact.processReference(text);
        };

        $scope.groupBy = function(property) {
            var url = "/status/ws/" + $routeParams.wsId + "/groupby/" + property;

            $location.path(url);
        };

        $scope.clearGroupBy = function() {
            var url = "/status/ws/" + $routeParams.wsId;

            $location.path(url);
        };

        $scope.getCurrentSelection = function() {
            return $scope.gridApi.selection.getSelectedRows();
        };

        $scope.encodeUrl = function(text) {
            return encodeURIComponent(encodeURIComponent(text));
        };

        $scope.csv = function() {
            deferred = $q.defer();
            delete searchFilter.confirmed;
            if ($scope.propertyFilterConfirmed === "Confirmed")
                searchFilter.confirmed = true;
            if ($scope.propertyFilterConfirmed === "Unconfirmed")
                searchFilter.confirmed = false;
            vulnsManager.getVulns($scope.workspace,
                                  null,
                                  null,
                                  searchFilter,
                                  null,
                                  null)
            .then(function(response) {
                deferred.resolve(csvService.generator($scope.columns, response.vulnerabilities, $scope.workspace));
            });
            return deferred.promise;
        };

        $scope.filterConfirmed = function (filter) {
            $scope.propertyFilterConfirmed = filter;
            $cookies.put('filterConfirmed', $scope.propertyFilterConfirmed);
            loadVulns();
        };

        // deletes the vulns in the array
        $scope.remove = function(aVulns) {
            aVulns.forEach(function(vuln) {
                vulnsManager.deleteVuln(vuln)
                    .then(function() {
                        loadVulns();
                    })
                    .catch(function(errorMsg) {
                        // TODO: show errors somehow
                        console.log("Error deleting vuln " + vuln._id + ": " + errorMsg);
                    });
            });
        };


        // action triggered from DELETE button
        $scope.delete = function() {
            _delete($scope.getCurrentSelection());
        };
        // delete only one vuln
        $scope.deleteVuln = function(vuln) {
            _delete([vuln]);
        };

        var _delete = function(vulns) {
            if(vulns.length > 0) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            var msg = "";
                            if(vulns.length == 1) {
                                msg = "A vulnerability will be deleted.";
                            } else {
                                msg = vulns.length + " vulnerabilities will be deleted.";
                            }
                            msg += " This action cannot be undone. Are you sure you want to proceed?";
                            return msg;
                        }
                    }
                });

                modal.result.then(function() {
                    $scope.remove(vulns);
                });
            } else {
                commonsFact.showMessage('No vulnerabilities were selected to delete');
            }
        };

        $scope.toggleConfirmVuln = function(vuln, confirm) {
            if($scope.workspaceData.active){
                _toggleConfirm([vuln], confirm);
            }
        };

        var _toggleConfirm = function(vulns, confirm) {
            var toggleConfirm = {'confirmed': !confirm},
            deferred = $q.defer(),
            promises = [];
            vulns.forEach(function(vuln) {
                promises.push(vulnsManager.updateVuln(vuln, toggleConfirm));
            });
            $q.all(promises).then(function(res) {
                if(confirm === true) {
                    loadVulns();
                }
            }, function(errorMsg){
                commonsFact.showMessage("Error updating vuln " + vuln.name + " (" + vuln._id + "): " + errorMsg);
            });
        };

        // action triggered from EDIT button
        $scope.edit = function() {
            _edit($scope.getCurrentSelection());
        };

        var _edit = function(vulns) {
           if (vulns.length == 1) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/statusReport/partials/modalEdit.html',
                    backdrop : 'static',
                    controller: 'modalEditCtrl as modal',
                    size: 'lg',
                    resolve: {
                        severities: function() {
                            return $scope.severities;
                        },
                        vuln: function() {
                            return vulns[0];
                        }
                    }
                });

                modal.result.then(function() {
                    loadVulns();
                });

            } else {
                commonsFact.showMessage('A vulnerability must be selected in order to edit');
            }
        };

        var editProperty = function(partial, controller, message, property, opts) {
            if(opts == undefined) {
                opts = {};
            }
            var resolve = {
                msg: function() {
                    return message;
                },
                options: function() {
                    return opts.options;
                }
            };
            var modal = $uibModal.open({
                templateUrl: partial,
                controller: controller,
                size: 'lg',
                resolve: resolve
            });
            modal.result.then(function(data) {
                $scope.getCurrentSelection().forEach(function(vuln) {
                    obj = {};
                    obj[property] = data;

                    if (opts.callback != undefined){
                        obj = opts.callback(vuln, data);
                    }

                    vulnsManager.updateVuln(vuln, obj).then(function(vulns){
                        loadVulns();
                    }, function(errorMsg){
                        // TODO: show errors somehow
                        console.log("Error updating vuln " + vuln._id + ": " + errorMsg);
                    });
                });
            });
        }

        $scope.editSeverity = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Enter the new severity:',
                'severity',
                {options: SEVERITIES});
        };

        $scope.editStatus = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Enter the new status:',
                'status',
                {options: STATUSES});
        };

        $scope.editEaseofresolution = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Enter the new easeofresolution:',
                'easeofresolution',
                {options: EASEOFRESOLUTION});
        };

        $scope.editPolicyviolations = function() {
            editProperty(
                'scripts/commons/partials/editArray.html',
                'commonsModalEditArray',
                'Enter the new policy violations:',
                'policyviolations',
                {callback: function (vuln, policyviolations) {
                    var violations = vuln.policyviolations.concat([]);
                    policyviolations.forEach(function(policyviolation) {
                        if(vuln.policyviolations.indexOf(policyviolation) == -1){
                            violations.push(policyviolation);
                        }
                    });

                    return {'policyviolations': violations};
                }}
                );
        };

        $scope.editReferences = function() {
            editProperty(
                'scripts/commons/partials/editArray.html',
                'commonsModalEditArray',
                'Enter the new references:',
                'refs',
                {callback: function (vuln, refs) {
                    var references = vuln.refs.concat([]);
                    refs.forEach(function(ref) {
                        if(vuln.refs.indexOf(ref) == -1){
                            references.push(ref);
                        }
                    });

                    return {'refs': references};
                }}
                );
        };

        $scope.editImpact = function() {
            editProperty(
                'scripts/commons/partials/editObject.html',
                'commonsModalEditObject',
                'Enter the new impact:',
                'impact',
                {
                    options: {
                        accountability: false,
                        availability: false,
                        confidentiality: false,
                        integrity: false
                    },
                    callback: function (vuln, impacts) {
                        var impact = {};
                        for(key in vuln.impact){
                            if(vuln.impact.hasOwnProperty(key)) {
                                impact[key] = vuln.impact[key];
                                if(impacts.hasOwnProperty(key)) {
                                    impact[key] = impacts[key];
                                }
                            }
                        }
                        return {'impact': impact};
                    }
                }
                );
        };

        $scope.editString = function(property, message_word) {
            var message;
            if(message_word) {
                message = 'Enter the new ' + message_word + ':';
            } else {
                message = 'Enter the new ' + property + ':';
            }
            editProperty(
                'scripts/commons/partials/editString.html',
                'commonsModalEditString',
                message,
                property);
        };

        $scope.editText = function(property, message_word) {
            var message;
            if(message_word) {
                message = 'Enter the new ' + message_word + ':';
            } else {
                message = 'Enter the new ' + property + ':';
            }
            editProperty(
                'scripts/commons/partials/editText.html',
                'commonsModalEditString',
                message,
                property);
        };

        $scope.editConfirm = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Confirm/Change to false positive:',
                'confirmed',
                {
                    options: ['Confirm', 'Set to false positive'],
                    callback: function(vuln, data) {
                        var property;
                        if(data === 'Confirm') {
                            property = {'confirmed': true};
                        } else {
                            property = {'confirmed': false};
                        }
                        return property;
                    }
                }
                );

        };

        $scope.editCWE = function() {
            var modal = $uibModal.open({
                templateUrl: 'scripts/commons/partials/editCWE.html',
                controller: 'commonsModalEditCWE',
                size: 'lg',
                resolve: {
                    msg: function() {
                        return 'Vulnerability template';
                    }
                }
            });
            modal.result.then(function(data) {
                $scope.getCurrentSelection().forEach(function(vuln) {
                    vulnsManager.updateVuln(vuln, data).then(function(vulns){
                    }, function(errorMsg){
                        // TODO: show errors somehow
                        console.log("Error updating vuln " + vuln._id + ": " + errorMsg);
                    });
                });
            });
        };

        var loadVulns = function() {
            delete searchFilter.confirmed;
            $scope.loading = true;
            if ($scope.propertyFilterConfirmed === 'Confirmed')
                searchFilter.confirmed = true;
            if ($scope.propertyFilterConfirmed === 'Unconfirmed'){
                searchFilter.confirmed = false;
            }
            // load all vulnerabilities
            vulnsManager.getVulns($scope.workspace,
                                  paginationOptions.page,
                                  paginationOptions.pageSize,
                                  searchFilter,
                                  paginationOptions.sortColumn,
                                  paginationOptions.sortDirection)
            .then(function(response) {
                $scope.loading = false;
                $scope.gridOptions.data = response.vulnerabilities;
                $scope.gridOptions.totalItems = response.count;

                // Add the total amount of vulnerabilities as an option for pagination
                // if it is larger than our biggest page size
                if ($scope.gridOptions.totalItems > paginationOptions.defaultPageSizes[paginationOptions.defaultPageSizes.length - 1]) {

                    $scope.gridOptions.paginationPageSizes = paginationOptions.defaultPageSizes.concat([$scope.gridOptions.totalItems]);

                    // sadly, this will load the vuln list again because it fires a paginationChanged event
                    if ($scope.gridOptions.paginationPageSize > $scope.gridOptions.totalItems)
                        $scope.gridOptions.paginationPageSize = $scope.gridOptions.totalItems;

                    // New vuln and MAX items per page setted => reload page size.
                    if ($scope.gridOptions.paginationPageSize === $scope.gridOptions.totalItems - 1)
                        $scope.gridOptions.paginationPageSize = $scope.gridOptions.totalItems;

                }
            });
        };

        $scope.new = function() {
            var modal = $uibModal.open({
                templateUrl: 'scripts/statusReport/partials/modalNew.html',
                backdrop : 'static',
                controller: 'modalNewVulnCtrl as modal',
                size: 'lg',
                resolve: {
                    severities: function() {
                        return $scope.severities;
                    },
                    workspace: function() {
                        return $scope.workspace;
                    }
                }
             });

            modal.result.then(function(data) {
                loadVulns();
            });
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            // TODO: It would be nice to find a way for changing
            // the url without reloading the controller
            if(window.location.hash.substring(1).indexOf('groupby') === -1) {
                var url = "/status/ws/" + $routeParams.wsId;
            } else {
                var url = "/status/ws/" + $routeParams.wsId + "/groupby/" + $routeParams.groupbyId;
            }

            if(search && params != "" && params != undefined) {
                var filter = commonsFact.parseSearchExpression(params);
                var URLParams = commonsFact.searchFilterToURLParams(filter);
                url += "/search/" + URLParams;
            }

            $location.path(url);
        };

        // toggles column show property
        $scope.toggleShow = function(column, show) {
            column = column.toLowerCase();
            $scope.columns[column] = !show;
            for (i = 0; i < $scope.gridOptions.columnDefs.length; i++) {
                if($scope.gridOptions.columnDefs[i].name === column || $scope.gridOptions.columnDefs[i].displayName === column) {
                    $scope.gridOptions.columnDefs[i].visible = !$scope.gridOptions.columnDefs[i].visible;
                    $scope.gridApi.grid.refresh();
                }
            }
            $cookies.put('SRcolumns', JSON.stringify($scope.columns));
            recalculateLastVisibleColSize();
        };

        var compareSeverities = function(a, b) {
            if(a !== 'undefined' || b !== 'undefined') {
                var res = 1;
                if($scope.severities.indexOf(a) === $scope.severities.indexOf(b)) { return 0; }
                if($scope.severities.indexOf(a) > $scope.severities.indexOf(b)) {
                  res = -1;
                }
                return res;
            }
        };

        $scope.selectionChange = function() {
            $scope.vulnWebSelected = $scope.getCurrentSelection().some(function(v) {
                return v.type === "VulnerabilityWeb"
            });
        };

        $scope.serviceSearch = function(srvName) {
            return $scope.encodeUrl(srvName);
        };

        function toggleFileUpload() {
            if($scope.fileUploadEnabled === false) {
                $scope.fileUploadEnabled = true;
            } else {
                $scope.fileUploadEnabled = false;
                $scope.fileToUpload = undefined;
            }
        }

        $scope.enableFileUpload = function() {
            if($scope.fileUploadEnabled === undefined) {
                $http.get('/_api/session').then(
                  function(d) {
                    $scope.csrf_token = d.data.csrf_token;
                    $scope.fileUploadEnabled = true;
                  }
                );
            } else {
              toggleFileUpload();
            }
        };
        $scope.uploadFile = function() {
            var fd = new FormData();
            fd.append('csrf_token', $scope.csrf_token);
            fd.append('file', $scope.fileToUpload);
            $http.post($scope.baseurl + '_api/v2/ws/' + $scope.workspace + '/upload_report', fd, {
                transformRequest: angular.identity,
                withCredentials: false,
                headers: {'Content-Type': undefined},
                responseType: "arraybuffer",
            }).then(
                function(d) {
                    $location.path("/dashboard/ws/" + $routeParams.wsId);
                },
                function(d){
                        commonsFact.showMessage("Error uploading report");
                }
            );
        };

        $scope.concatForTooltip = function (items, isArray, useDoubleLinebreak) {
            var elements = [];
            for (var property in items) {
                if (items.hasOwnProperty(property)) {
                    if (isArray) {
                        elements.push(items[property])
                    }
                    else {
                        elements.push(property)
                    }
                }
            }

            return elements.join("\n" + (useDoubleLinebreak ? "\n" : ""));
        };

        init();
    }]);
