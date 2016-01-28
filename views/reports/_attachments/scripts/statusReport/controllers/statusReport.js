// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('statusReportCtrl', 
                    ['$scope', '$filter', '$routeParams',
                    '$location', '$uibModal', '$cookies', '$q', '$window', 'BASEURL',
                    'SEVERITIES', 'EASEOFRESOLUTION', 'hostsManager',
                    'vulnsManager', 'workspacesFact', 'csvService', 'uiGridConstants',
                    function($scope, $filter, $routeParams,
                        $location, $uibModal, $cookies, $q, $window, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, hostsManager,
                        vulnsManager, workspacesFact, csvService, uiGridConstants) {
        $scope.baseurl;
        $scope.columns;
        $scope.easeofresolution;
        $scope.expression;
        $scope.interfaces;
        $scope.reverse;
        $scope.severities;
        $scope.search;
        $scope.searchParams;
        $scope.sortField;
        $scope.vulns;
        $scope.workspaces;
        $scope.currentPage;
        $scope.newCurrentPage;
        $scope.newPageSize;
        $scope.gridOptions;

        $scope.vulnWebSelected;
        $scope.confirmed = false;
        var allVulns;

        init = function() {
            $scope.baseurl = BASEURL;
            $scope.severities = SEVERITIES;
            $scope.easeofresolution = EASEOFRESOLUTION;
            $scope.propertyGroupBy = $routeParams.groupbyId;
            $scope.sortField = 'metadata.create_time';
            $scope.reverse = true;
            $scope.vulns = [];
            $scope.selected = false;

            $scope.gridOptions = {
                multiSelect: true,
                enableSelectAll: true,
                enableColumnMenus: false,
                enableRowSelection: true,
                enableRowHeaderSelection: false,
                paginationPageSizes: [10, 50, 75, 100],
                paginationPageSize: 10,
                enableHorizontalScrollbar: 0,
                treeRowHeaderAlwaysVisible: false,
                enableGroupHeaderSelection: true,
                rowHeight: 95
            };
            $scope.gridOptions.columnDefs = [];

            if ($cookies.get('pageSize') !== undefined) $scope.gridOptions.paginationPageSize = parseInt($cookies.get('pageSize'));

            $scope.gridOptions.onRegisterApi = function(gridApi){
                //set gridApi on scope
                $scope.gridApi = gridApi;
                $scope.gridApi.selection.on.rowSelectionChanged( $scope, function ( rowChanged ) {
                    if ( typeof(rowChanged.treeLevel) !== 'undefined' && rowChanged.treeLevel > -1 ) {
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
                    $cookies.put('pageSize', pageSize);
                    $scope.gridApi.selection.clearSelectedRows();
                });
            };

            // load all workspaces
            workspacesFact.list().then(function(wss) {
                $scope.workspaces = wss;
            });

            // current workspace
            $scope.workspace = $routeParams.wsId;
            $scope.interfaces = [];
            // current search
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            $scope.expression = {};
            if($cookies.get('confirmed') === 'true') $scope.confirmed = true;
            if($scope.confirmed === true) {
                if($scope.search !== undefined) {
                    $scope.search = $scope.search.concat("&confirmed=true");
                } else {
                    $scope.search = "confirmed=true";
                }
            }
            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                // search expression for filter
                $scope.expression = $scope.decodeSearch($scope.search);
                // search params for search field, which shouldn't be used for filtering
                $scope.searchParams = $scope.stringSearch($scope.expression);
            }
            $scope.hash = window.location.hash;
            if(window.location.hash.substring(1).indexOf('search') !== -1) {
                $scope.hash = $scope.hash.slice(0, window.location.hash.indexOf('search') - 1);
            }

            // load all vulnerabilities
            vulnsManager.getVulns($scope.workspace).then(function(vulns) {
                tmp_data = $filter('orderObjectBy')(vulnsManager.vulns, $scope.propertyGroupBy, true);
                $scope.gridOptions.data = $filter('filter')(tmp_data, $scope.expression);

                $scope.gridOptions.total = vulns.length;
                if($scope.gridOptions.total > $scope.gridOptions.paginationPageSize && $scope.gridOptions.total > 100) {
                    $scope.gridOptions.paginationPageSizes.push($scope.gridOptions.total);
                }
            });

            $scope.columns = {
                "date":             true,
                "name":             true,
                "severity":         true,
                "service":          true,
                "target":           true,
                "desc":             true,
                "resolution":       false,
                "data":             true,
                "easeofresolution": false,
                "status":           false,
                "website":          false,
                "path":             false,
                "request":          false,
                "refs":             true,
                "evidence":         false,
                "hostnames":        false,
                "impact":           false,
                "method":           false,
                "params":           false,
                "pname":            false,
                "query":            false,
                "response":         false,
                "web":              false
            };

            // created object for columns cookie columns
            if(typeof($cookies.get('SRcolumns')) != 'undefined'){
                var arrayOfColumns = $cookies.get('SRcolumns').replace(/[{}"']/g, "").split(',');
                arrayOfColumns.forEach(function(column){
                    var columnFinished = column.split(':');
                    if ($scope.columns.hasOwnProperty(columnFinished[0])) {
                        $scope.columns[columnFinished[0]] = columnFinished[1] === "true" ? true: false;
                    }
                });
            }

            $scope.gridOptions.columnDefs.push({ name: 'selectAll', width: '20', headerCellTemplate: "<i class=\"fa fa-check cursor\" ng-click=\"grid.appScope.selectAll()\" ng-style=\"{'opacity':(grid.appScope.selected === true) ? '1':'0.6'}\"></i>", pinnedLeft:true });
            $scope.gridOptions.columnDefs.push({ name: 'confirmVuln', width: '40', headerCellTemplate: "<div></div>", cellTemplate: 'scripts/statusReport/partials/ui-grid/confirmbutton.html' });
            $scope.gridOptions.columnDefs.push({ name: 'deleteVuln', width: '40', headerCellTemplate: "<div></div>", cellTemplate: 'scripts/statusReport/partials/ui-grid/deletebutton.html' });
            $scope.gridOptions.columnDefs.push({ name: 'editVuln', width: '30', headerCellTemplate: "<div></div>", cellTemplate: 'scripts/statusReport/partials/ui-grid/editbutton.html' });

            var header = '<div ng-class="{ \'sortable\': sortable }">'+
                    '       <div class="ui-grid-cell-contents" col-index="renderIndex" title="TOOLTIP">{{ col.displayName CUSTOM_FILTERS }}'+
                    '           <a href="" ng-click="grid.appScope.toggleShow(col.displayName, true)">'+
                    '               <span style="color:#000;" class="glyphicon glyphicon-remove"></span>'+
                    '           </a>'+
                    '           <span ui-grid-visible="col.sort.direction" ng-class="{ \'ui-grid-icon-up-dir\': col.sort.direction == asc, \'ui-grid-icon-down-dir\': col.sort.direction == desc, \'ui-grid-icon-blank\': !col.sort.direction }">&nbsp;</span>'+
                    '       </div>'+
                    '       <div class="ui-grid-column-menu-button" ng-if="grid.options.enableColumnMenus && !col.isRowHeader  && col.colDef.enableColumnMenu !== false" ng-click="toggleMenu($event)" ng-class="{\'ui-grid-column-menu-button-last-col\': isLastCol}">'+
                    '           <i class="ui-grid-icon-angle-down">&nbsp;</i>'+
                    '       </div>'+
                    '       <div ui-grid-filter></div>'+
                    '   </div>';

            $scope.gridOptions.columnDefs.push({ name : 'metadata.create_time',
                displayName : "date",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/datecolumn.html',
                headerCellTemplate: header,
                width: '90',
                visible: $scope.columns["date"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'name',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/namecolumn.html',
                headerCellTemplate: header,
                maxWidth: '230',
                visible: $scope.columns["name"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'severity',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/severitycolumn.html',
                headerCellTemplate: header,
                type: 'string',
                width: '110',
                visible: $scope.columns["severity"],
                sortingAlgorithm: compareSeverities
            });
            $scope.gridOptions.columnDefs.push({ name : 'service',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/servicecolumn.html',
                headerCellTemplate: header,
                width: '110',
                visible: $scope.columns["service"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'target',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/targetcolumn.html',
                headerCellTemplate: header,
                width: '120',
                visible: $scope.columns["target"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'desc',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/desccolumn.html',
                headerCellTemplate: header,
                minWidth: '300',
                maxWidth: '400',
                visible: $scope.columns["desc"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'resolution',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["resolution"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'data',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["data"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'easeofresolution',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["easeofresolution"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'status',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["status"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'website',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["website"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'path',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["path"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'request',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["request"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'refs',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/refscolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["refs"]
            });
            $scope.gridOptions.columnDefs.push({ name : '_attachments',
                displayName: "evidence",
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/evidencecolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["evidence"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'hostnames',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/hostnamescolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["hostnames"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'impact',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/impactcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["impact"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'method',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["method"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'params',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["params"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'pname',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["pname"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'query',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/defaultcolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["query"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'response',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/resolutioncolumn.html',
                headerCellTemplate: header,
                visible: $scope.columns["response"]
            });
            $scope.gridOptions.columnDefs.push({ name : 'web',
                cellTemplate: 'scripts/statusReport/partials/ui-grid/columns/webcolumn.html',
                headerCellTemplate: header,
                width: '80',
                visible: $scope.columns["web"]
            });

            $scope.vulnWebSelected = false;

            var count = 0;
            for(key in $scope.columns) {
                if($scope.columns.hasOwnProperty(key) && $scope.columns[key] == true) {
                    count++;
                    if(key === $scope.propertyGroupBy) {
                        $scope.gridOptions.columnDefs[count + 3].grouping = { groupPriority: 0 };
                        $scope.gridOptions.columnDefs[count + 3].sort = { priority: 0, direction: 'asc' }
                    }
                }
            }
        };

        $scope.ifTooltip = function(text) {
            if(text !== undefined && text.length > 450) {
                return text;
            }
        };

        $scope.confirmedTooltip = function(isConfirmed) {
            var res = "";
            if(isConfirmed === true) {
                res = "Change to false positive";
            } else {
                res = "Confirm";
            }
            return res;
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
            var url = 'http://google.com/',
            url_pattern = new RegExp('^(http|https):\\/\\/?');

            var cve_pattern = new RegExp(/^CVE-\d{4}-\d{4,7}$/),
            cwe_pattern = new RegExp(/^CWE(-|:)\d{1,7}$/),
            edb_pattern = new RegExp(/^EDB-ID:\s?\d{1,}$/),
            osvdb_pattern = new RegExp(/^OSVDB:\s?\d{1,}$/);

            var cve = text.search(cve_pattern),
            cwe = text.search(cwe_pattern),
            edb = text.search(edb_pattern),
            osvdb = text.search(osvdb_pattern);

            if(url_pattern.test(text)) {
                url = text;
            } else if(cve > -1) {
                url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + text.substring(cve + 4);
            } else if(cwe > -1) {
                url = "https://cwe.mitre.org/data/definitions/" + text.substring(cwe + 4) + ".html";
            } else if(osvdb > -1) {
                url = "http://osvdb.org/show/osvdb/" + text.substring(osvdb + 6);
            } else if(edb > -1) {
                url = "https://www.exploit-db.com/exploits/" + text.substring(edb + 7);
            } else {
                url += 'search?q=' + text;
            }
            
            return url;
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
            tmp_vulns = $filter('filter')($scope.gridOptions.data, $scope.expression);
            return csvService.generator($scope.columns, tmp_vulns, $scope.workspace);
        };

        $scope.toggleFilter = function(expression) {
            if(expression["confirmed"] === undefined) {
                expression["confirmed"] = true;
                $scope.expression = expression;
                $cookies.put('confirmed', $scope.expression.confirmed);
                loadVulns();
                $scope.confirmed = true;
            } else {
                $scope.expression = {};
                for(key in expression) {
                    if(expression.hasOwnProperty(key)) {
                        if(key !== "confirmed") {
                            $scope.expression[key] = expression[key];
                        }
                    }
                }
                $cookies.put('confirmed', $scope.expression.confirmed);
                loadVulns();
                $scope.confirmed = false;
            }
        };

        showMessage = function(msg) {
            var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function() {
                            return msg;
                        }
                    }
                });
        }

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

        _delete = function(vulns) {
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
                showMessage('No vulnerabilities were selected to delete');
            }
        };

        $scope.toggleConfirmVuln = function(vuln, confirm) {
            _toggleConfirm([vuln], confirm);
        };

        _toggleConfirm = function(vulns, confirm) {
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
                showMessage("Error updating vuln " + vuln.name + " (" + vuln._id + "): " + errorMsg);
            });
        };

        // action triggered from EDIT button
        $scope.edit = function() {
            _edit($scope.getCurrentSelection());
        };

        $scope.editVuln = function(vuln) {
            _edit([vuln]);
        };

        _edit = function(vulns) {
           if (vulns.length == 1) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/statusReport/partials/modalEdit.html',
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
                modal.result.then(function(data) {
                    vulnsManager.updateVuln(vulns[0], data).then(function(){
                    }, function(errorMsg){
                        showMessage("Error updating vuln " + vulns[0].name + " (" + vulns[0]._id + "): " + errorMsg);
                    });
                });
            } else {
                showMessage('A vulnierabilty must be selected in order to edit');
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

        $scope.editEaseofresolution = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Enter the new easeofresolution:',
                'easeofresolution',
                {options: EASEOFRESOLUTION});
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
                        return 'CWE template';
                    }
                }
            });
            modal.result.then(function(data) {
                $scope.selectedVulns().forEach(function(vuln) {
                    var references = vuln.refs.concat([]);
                    data.refs.forEach(function(ref) {
                        if(vuln.refs.indexOf(ref) == -1){
                            references.push(ref);
                        }
                    });
                    data.refs = references;                    

                    vulnsManager.updateVuln(vuln, data).then(function(vulns){
                    }, function(errorMsg){
                        // TODO: show errors somehow
                        console.log("Error updating vuln " + vuln._id + ": " + errorMsg);
                    });
                });
            });
        };

        $scope.insert = function(vuln) {
            vulnsManager.createVuln($scope.workspace, vuln).then(function() {
                loadVulns();
            }, function(message) {
                var msg = "The vulnerability couldn't be created";
                if(message == "409") {
                    msg += " because a vulnerability with the same parameters already exists in this Workspace";
                }
                showMessage(msg);
            });
            /*
            // this shouldnt be necessary, we should use Angular formatting options directly in the partial
            //formating the date
            var d = new Date(0);
            d.setUTCSeconds(vuln.date);
            d = d.getDate() + "/" + (d.getMonth()+1) + "/" + d.getFullYear();
            vuln.date = d;
            */
        };

        loadVulns = function(property) {
            // load all vulnerabilities
            if (!property) property = "name";
            tmp_data = $filter('orderObjectBy')(vulnsManager.vulns, property, true);
            $scope.gridOptions.data = $filter('filter')(tmp_data, $scope.expression);
        };

        $scope.new = function() {
            var modal = $uibModal.open({
                templateUrl: 'scripts/statusReport/partials/modalNew.html',
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
                $scope.insert(data);
            });
        };

        // encodes search string in order to send it through URL
        $scope.encodeSearch = function(search) {
            var i = -1,
            encode = "",
            params = search.split(" "),
            chunks = {};

            params.forEach(function(chunk) {
                i = chunk.indexOf(":");
                if(i > 0) {
                    chunks[chunk.slice(0, i)] = chunk.slice(i+1);
                } else {
                    if(!chunks.hasOwnProperty("free")) {
                        chunks.free = "";
                    }
                    chunks.free += " ".concat(chunk);
                }
            });

            if(chunks.hasOwnProperty("free")) {
                chunks.free = chunks.free.slice(1);
            }

            for(var prop in chunks) {
                if(chunks.hasOwnProperty(prop)) {
                    if(chunks.prop != "") {
                        encode += "&" + encodeURIComponent(prop) + "=" + encodeURIComponent(chunks[prop]);
                    }
                }
            }
            return encode.slice(1);
        };

        // decodes search parameters to object in order to use in filter
        $scope.decodeSearch = function(search) {
            var i = -1,
            decode = {},
            params = search.split("&");

            params.forEach(function(param) {
                i = param.indexOf("=");
                decode[decodeURIComponent(param.slice(0,i))] = decodeURIComponent(param.slice(i+1));
            });

            if(decode.hasOwnProperty("free")) {
                decode['$'] = decode.free;
                delete decode.free;
            }

            return decode;
        };

        // converts current search object to string to be displayed in search field
        $scope.stringSearch = function(obj) {
            var search = "";

            for(var prop in obj) {
                if(obj.hasOwnProperty(prop)) {
                    if(search != "") {
                        search += " ";
                    }
                    if(prop == "$") {
                        search += obj[prop];
                    } else {
                        if(prop !== "confirmed"){
                            search += prop + ":" + obj[prop];
                        }
                    }
                }
            }

            return search;
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            if(window.location.hash.substring(1).indexOf('groupby') === -1) {
                var url = "/status/ws/" + $routeParams.wsId;
            } else {
                var url = "/status/ws/" + $routeParams.wsId + "/groupby/" + $routeParams.groupbyId;
            }

            if(search && params != "" && params != undefined) {
                url += "/search/" + $scope.encodeSearch(params);
            }

            $location.path(url);
        };
        
        // toggles column show property
        $scope.toggleShow = function(column, show) {
            column = column.toLowerCase();
            $scope.columns[column] = !show;
            for (i = 0;i < $scope.gridOptions.columnDefs.length; i++) {
                if($scope.gridOptions.columnDefs[i].name === column || $scope.gridOptions.columnDefs[i].displayName === column) {
                    $scope.gridOptions.columnDefs[i].visible = !$scope.gridOptions.columnDefs[i].visible;
                    $scope.gridApi.grid.refresh();
                }
            }
            $cookies.put('SRcolumns', JSON.stringify($scope.columns));
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

        init();
    }]);
