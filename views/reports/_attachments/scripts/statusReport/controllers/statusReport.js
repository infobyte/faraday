// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('statusReportCtrl', 
                    ['$scope', '$filter', '$routeParams',
                    '$location', '$modal', '$cookies', '$q', '$window', 'BASEURL',
                    'SEVERITIES', 'EASEOFRESOLUTION', 'hostsManager',
                    'vulnsManager', 'workspacesFact', 'csvService',
                    function($scope, $filter, $routeParams,
                        $location, $modal, $cookies, $q, $window, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, hostsManager,
                        vulnsManager, workspacesFact, csvService) {
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
        $scope.pageSize;
        $scope.newPageSize;

        $scope.vulnWebSelected;

        init = function() {
            $scope.baseurl = BASEURL;
            $scope.severities = SEVERITIES;
            $scope.easeofresolution = EASEOFRESOLUTION;
            $scope.sortField = 'metadata.create_time';
            $scope.reverse = true;
            $scope.vulns = [];

            $scope.pageSize = 10;
            $scope.currentPage = 0;
            $scope.newCurrentPage = 0;
 
            if (!isNaN(parseInt($cookies.pageSize)))
                $scope.pageSize = parseInt($cookies.pageSize);
            $scope.newPageSize = $scope.pageSize;

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
            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                // search expression for filter
                $scope.expression = $scope.decodeSearch($scope.search);
                // search params for search field, which shouldn't be used for filtering
                $scope.searchParams = $scope.stringSearch($scope.expression);
            }

            // load all vulnerabilities
            vulnsManager.getVulns($scope.workspace).then(function(vulns) {
                $scope.vulns = vulnsManager.vulns;
            });

            // created object for columns cookie columns
            if(typeof($cookies.SRcolumns) != 'undefined') {
                var objectoSRColumns = {};
                var arrayOfColumns = $cookies.SRcolumns.replace(/[{}"']/g, "").split(',');
                arrayOfColumns.forEach(function(column){
                    var columnFinished = column.split(':');
                    if(columnFinished[1] == "true") objectoSRColumns[columnFinished[0]] = true; else objectoSRColumns[columnFinished[0]] = false;
                });
            }
            // set columns to show and hide by default
            $scope.columns = objectoSRColumns || {
                "date":             true,
                "severity":         true,
                "target":           true,
                "name":             true,
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
            
            $scope.vulnWebSelected = false;
        };

        $scope.processReference = function(text) {
            var url = 'http://google.com/',
            url_pattern = new RegExp('^(http|https):\\/\\/?');

            var cve_pattern = new RegExp(/^CVE-\d{4}-\d{4,7}$/),
            cwe_pattern = new RegExp(/^CWE-\d{1,7}$/),
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
                url = "https://cwe.mitre.org/data/definitions/" + text.substring(cwe + 3) + ".html";
            } else if(osvdb > -1) {
                url = "http://osvdb.org/show/osvdb/" + text.substring(osvdb + 6);
            } else if(edb > -1) {
                url = "https://www.exploit-db.com/exploits/" + text.substring(edb + 7);
            } else {
                url += 'search?q=' + text;
            }
            
            $window.open(url, '_blank');
        };

        $scope.selectedVulns = function() {
            selected = [];
            var tmp_vulns = $filter('orderObjectBy')($scope.vulns, $scope.sortField, $scope.reverse);
            tmp_vulns = $filter('filter')(tmp_vulns, $scope.expression);
            tmp_vulns = tmp_vulns.splice($scope.pageSize * $scope.currentPage, $scope.pageSize);
            tmp_vulns.forEach(function(vuln) {
                if (vuln.selected_statusreport_controller) {
                    selected.push(vuln);
                }
            });
            return selected;
        }

        $scope.csv = function() {
            tmp_vulns = $filter('filter')($scope.vulns, $scope.expression);
            return csvService.generator($scope.columns, tmp_vulns, $scope.workspace);
        };

        showMessage = function(msg) {
            var modal = $modal.open({
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
                    .then(function() {})
                    .catch(function(errorMsg) {
                        // TODO: show errors somehow
                        console.log("Error deleting vuln " + vuln._id + ": " + errorMsg);
                    });
            });
        };


        // action triggered from DELETE button
        $scope.delete = function() {
            _delete($scope.selectedVulns());
        };
        // delete only one vuln
        $scope.deleteVuln = function(vuln) {
            _delete([vuln]);
        };

        _delete = function(vulns) {
            if(vulns.length > 0) {
                var modal = $modal.open({
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

        // action triggered from EDIT button
        $scope.edit = function() {
            _edit($scope.selectedVulns());
        };

        $scope.editVuln = function(vuln) {
            _edit([vuln]);
        };

        _edit = function(vulns) {
           if (vulns.length == 1) {
                var modal = $modal.open({
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
            var modal = $modal.open({
                templateUrl: partial,
                controller: controller,
                size: 'lg',
                resolve: resolve
            });
            modal.result.then(function(data) {
                $scope.selectedVulns().forEach(function(vuln) {
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

        $scope.editCWE = function() {
            var modal = $modal.open({
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

        $scope.new = function() {
            var modal = $modal.open({
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

        $scope.checkAll = function() {
            if(!$scope.selectall) {
                $scope.selectall = true;
            } else {
                $scope.selectall = false;
            }

            var tmp_vulns = $filter('orderObjectBy')($scope.vulns, $scope.sortField, $scope.reverse);
            tmp_vulns = $filter('filter')(tmp_vulns, $scope.expression);
            tmp_vulns = tmp_vulns.splice($scope.pageSize * $scope.currentPage, $scope.pageSize);
            tmp_vulns.forEach(function(v,k) {
                v.selected_statusreport_controller = $scope.selectall;
            });

        };

        $scope.go = function() {
            $scope.pageSize = $scope.newPageSize;
            $cookies.pageSize = $scope.pageSize;
            $scope.currentPage = 0;
            if($scope.newCurrentPage <= parseInt($scope.vulns.length/$scope.pageSize)
                    && $scope.newCurrentPage > -1 && !isNaN(parseInt($scope.newCurrentPage))) {
                $scope.currentPage = $scope.newCurrentPage;
            }
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
                        search += prop + ":" + obj[prop];
                    }
                }
            }

            return search;
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            var url = "/status/ws/" + $routeParams.wsId;

            if(search && params != "" && params != undefined) {
                url += "/search/" + $scope.encodeSearch(params);
            }

            $location.path(url);
        };
        
        // toggles column show property
        $scope.toggleShow = function(column, show) {
            $scope.columns[column] = !show;
            $cookies.SRcolumns = JSON.stringify($scope.columns);
        };

        // toggles sort field and order
        $scope.toggleSort = function(field) {
            $scope.toggleSortField(field);
            $scope.toggleReverse();
        };

        // toggles column sort field
        $scope.toggleSortField = function(field) {
            $scope.sortField = field;
        };

        // toggle column sort order
        $scope.toggleReverse = function() {
            $scope.reverse = !$scope.reverse;
        };

        $scope.selectionChange = function() {
            $scope.vulnWebSelected = $scope.selectedVulns().some(function(v) {
                return v.type === "VulnerabilityWeb"
            });
        };

        init();
    }]);
