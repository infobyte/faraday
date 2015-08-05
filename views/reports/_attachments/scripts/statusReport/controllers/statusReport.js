// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('statusReportCtrl', 
                    ['$scope', '$filter', '$routeParams',
                    '$location', '$modal', '$cookies', '$q', 'BASEURL',
                    'SEVERITIES', 'EASEOFRESOLUTION', 'hostsManager',
                    'vulnsManager', 'workspacesFact',
                    function($scope, $filter, $routeParams,
                        $location, $modal, $cookies, $q, BASEURL,
                        SEVERITIES, EASEOFRESOLUTION, hostsManager,
                        vulnsManager, workspacesFact) {
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
            if(typeof($cookies.SRcolumns) != 'undefined'){
                var objectoSRColumns = {};
                var arrayOfColumns = $cookies.SRcolumns.replace(/[{}"']/g, "").split(',');
                arrayOfColumns.forEach(function(column){
                    var columnFinished = column.split(':');
                    if(columnFinished[1] == "true") objectoSRColumns[columnFinished[0]] = true; else objectoSRColumns[columnFinished[0]] = false;
                });
            }
            // set columns to show and hide by default
            $scope.columns = objectoSRColumns || {
                "data":             true,
                "date":             true,
                "desc":             true,
                "easeofresolution": false,
                "evidence":         false,
                "hostnames":        false,
                "impact":           false,
                "method":           false,
                "name":             true,
                "params":           false,
                "path":             false,
                "pname":            false,
                "query":            false,
                "refs":             true,
                "request":          false,
                "response":         false,
                "resolution":       false,
                "severity":         true,
                "status":           false,
                "target":           true,
                "web":              false,
                "website":          false
            };
            
            $scope.vulnWebSelected = false;
        };

        $scope.selectedVulns = function() {
            selected = [];
            $scope.vulns.forEach(function(vuln) {
                if (vuln.selected_statusreport_controller) {
                    selected.push(vuln);
                }
            });
            return selected;
        }


        // returns scope vulns as CSV obj
        // toggles column sort field
        cleanCSV = function(field) {
            return field.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'").replace(/[\n\r]/g, "%0A").replace(/[,]/g, "%2c");
        };

        $scope.toCSV = function() {
            var method  = "",
            website     = "",
            desc        = "",
            easeofres   = "",
            impact      = "",
            text        = "",
            path        = "",
            pname       = "",
            params      = "",
            query       = "",
            refs        = "",
            request     = "",
            response    = "",
            resolution  = "",
            content     = "\"Date\", \"Web\", \"Status\", \"Severity\", "+
                "\"Name\", \"Target\", \"Description\", "+
                "\"Data\", \"Method\", \"Path\", \"Param Name\", \"Params\", "+
                "\"Query\", \"References\", \"Request\", \"Response\", \"Resolution\",\"Website\", "+
                "\"Ease of Resolution\", \"Impact\"\n";
            
            $scope.vulns.then(function(vs) {
                forEach(function(v) {
                    method      = "";
                    website     = "";
                    desc        = "";
                    easeofres   = "",
                    impact      = JSON.stringify(v.impact),
                    text        = "";
                    path        = "";
                    pname       = "";
                    params      = "";
                    query       = "";
                    refs        = "";
                    request     = "";
                    response    = "";
                    resolution  = "";
                    refs        = v.refs.toString();

                    if(typeof(v.desc) != "undefined" && v.desc != null)                 desc          = cleanCSV(v.desc);
                    if(typeof(v.data) != "undefined" && v.data != null)                 text          = cleanCSV(v.data);
                    if(typeof(v.resolution) != "undefined" && v.resolution != null)     resolution    = cleanCSV(v.resolution);
                    if(typeof(refs) != "undefined" && refs != null){
                        refs = cleanCSV(refs);
                        refs = refs.replace(/%2c/g,"%0A");
                    }
                    if(typeof(impact) != "undefined" && impact != null){
                        impact = cleanCSV(impact);
                        impact = impact.replace(/%2c/g,"%0A");
                    }
                    if(v.type === "VulnerabilityWeb") {
                        if(typeof(v.method) != "undefined" && v.method != null)         method      = cleanCSV(v.method);
                        if(typeof(v.website) != "undefined" && v.website != null)       website     = cleanCSV(v.website);
                        if(typeof(v.path) != "undefined" && v.path != null)             path        = cleanCSV(v.path);
                        if(typeof(v.pname) != "undefined" && v.pname != null)           pname       = cleanCSV(v.pname);
                        if(typeof(v.params) != "undefined" && v.params != null)         params      = cleanCSV(v.params);
                        if(typeof(v.query) != "undefined" && v.query != null)           query       = cleanCSV(v.query);
                        if(typeof(refs) != "undefined" && refs != null){
                            refs = cleanCSV(refs);
                            refs = refs.replace(/%2c/g,"%0A");
                        }
                        if(typeof(v.request) != "undefined" && v.request != null)       request     = cleanCSV(v.request);
                        if(typeof(v.response) != "undefined" && v.response != null)     response    = cleanCSV(v.response);
                        if(typeof(v.resolution) != "undefined" && v.resolution != null) resolution  = cleanCSV(v.resolution);
                    }

                    content += "\""+v.date+"\","+
                        " \""+v.web+"\","+
                        " \"Vulnerable\","+
                        " \""+v.severity+"\","+
                        " \""+v.name+"\","+
                        " \""+v.target+"\","+
                        " \""+desc+"\","+
                        " \""+text+"\","+
                        " \""+method+"\","+
                        " \""+path+"\","+
                        " \""+pname+"\","+
                        " \""+params+"\","+
                        " \""+query+"\","+
                        " \""+refs+"\","+
                        " \""+request+"\","+
                        " \""+response+"\","+
                        " \""+resolution+"\","+
                        " \""+website+"\","+
                        " \""+impact+"\","+
                        " \""+easeofres+"\""+
                        "\n";
                });
            });

            var obj = {
                "content":  content,
                "extension": "csv",
                "title":    "SR-" + $scope.workspace,
                "type": "text/csv"
            };
            
            return obj;
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
            if($scope.selectedVulns().length > 0) {
                var modal = $modal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            var msg = "";
                            if($scope.selectedVulns().length == 1) {
                                msg = "A vulnerability will be deleted.";
                            } else {
                                msg = $scope.selectedVulns().length + " vulnerabilities will be deleted.";
                            }
                            msg += " This action cannot be undone. Are you sure you want to proceed?";
                            return msg;
                        }
                    }
                });

                modal.result.then(function() {
                    $scope.remove($scope.selectedVulns());
                });
            } else {
                showMessage('No vulnerabilities were selected to delete');
            }
        };

        // action triggered from EDIT button
        $scope.edit = function() {
            if ($scope.selectedVulns().length == 1) {
                var modal = $modal.open({
                    templateUrl: 'scripts/statusReport/partials/modalEdit.html',
                    controller: 'modalEditCtrl as modal',
                    size: 'lg',
                    resolve: {
                        severities: function() {
                            return $scope.severities;
                        },
                        vuln: function() {
                            return $scope.selectedVulns()[0];
                        }
                    }
                });
                modal.result.then(function(data) {
                    vulnsManager.updateVuln($scope.selectedVulns()[0], data).then(function(){
                    }, function(errorMsg){
                        showMessage("Error updating vuln " + $scope.selectedVulns()[0].name + " (" + $scope.selectedVulns()[0]._id + "): " + errorMsg);
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
        }

        $scope.editEaseofresolution = function() {
            editProperty(
                'scripts/commons/partials/editOptions.html',
                'commonsModalEditOptions',
                'Enter the new easeofresolution:',
                'easeofresolution',
                {options: EASEOFRESOLUTION});
        }

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
        }

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
        }

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
        }

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
        }

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
        }

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

            var orderObject = $filter('orderObjectBy')($scope.vulns, $scope.sortField, $scope.reverse);
            var tmp_vulns = $filter('limitTo')(orderObject, $scope.pageSize, $scope.currentPage * $scope.pageSize);
            angular.forEach($filter('filter')(tmp_vulns), function(v,k) {
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
            return encodeURI(encode.slice(1));
        };

        // decodes search parameters to object in order to use in filter
        $scope.decodeSearch = function(search) {
            var i = -1,
            decode = {},
            params = decodeURI(search).split("&");

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
