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
        $scope.currentPage;
        $scope.easeofresolution;
        $scope.expression;
        $scope.interfaces;
        $scope.numberOfPages;
        $scope.pageSize;
        $scope.reverse;
        $scope.severities;
        $scope.search;
        $scope.searchParams;
        $scope.showPagination;
        $scope.sortField;
        $scope.vulns;
        $scope.workspaces;

        init = function() {
            $scope.baseurl = BASEURL;
            $scope.severities = SEVERITIES;
            $scope.easeofresolution = EASEOFRESOLUTION;
            $scope.sortField = 'date';
            $scope.reverse = true;
            $scope.showPagination = 1;
            $scope.currentPage = 0;

            // set custom pagination if possible
            if(typeof($cookies.pageSize) == "undefined") {
                $scope.pageSize = 10;
                $scope.pagination = 10;
            } else { 
                $scope.pageSize = parseInt($cookies.pageSize);
                $scope.pagination = parseInt($cookies.pageSize);
            }

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
                $scope.vulns = $filter('filter')(vulns, $scope.expression);
                $scope.numberOfPages = $scope.calculateNumberOfPages(); 
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
        };

        // this methos recieves an array of vulns and returns
        // a new array with the selected vulns, if justIds is not true,
        // or a new array with the ids of the selected vulns, if it's true
        getSelectedVulns = function(aVulns, justIds){
            var selected = [];

            aVulns.forEach(function(v) {
                if(v.selected) {
                    if (justIds === true){
                        selected.push(v._id);
                    } else {
                        selected.push(v);
                    }
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

        // deletes the vulns in the array
        $scope.remove = function(ids) {
            ids.forEach(function(id){
                vulnsManager.deleteVuln($scope.workspace, id).then(function(){
                    var index = -1;
                    for (var i=0; i < $scope.vulns.length; i++){
                        if ($scope.vulns[i]._id === id) {
                            index = i;
                            break;
                        }
                    }
                    $scope.vulns.splice(index, 1);
                }), function(error){
                    console.log(error);
                }
            });
        };

        // updates all vulns with selected == true
        // I BROKE THIS DO IT FROM SCRATCH WITH vulnsManager
        $scope.update = function(data) {
            $scope.vulns = [];
           
            data.vulns.forEach(function(v) {
                if(v.selected) {
                    if(typeof(data.severity) == "string") v.severity = data.severity;
                    if(typeof(data.easeofresolution) == "string") v.easeofresolution = data.easeofresolution;
                    if(typeof(data.name) != "undefined") v.name = data.name;
                    if(typeof(data.desc) != "undefined") v.desc = data.desc;
                    if(typeof(data.data) != "undefined") v.data = data.data;
                    if(typeof(data.refs) != "undefined") v.refs = data.refs;
                    if(typeof(data.impact) != "undefined") v.impact = data.impact;
                    if(typeof(data.resolution) != "undefined") v.resolution = data.resolution;
                    v.evidence = data.evidence;
                    if(v.web) {
                        if(typeof(data.method) != "undefined") v.method = data.method;
                        if(typeof(data.params) != "undefined") v.params = data.params;
                        if(typeof(data.path) != "undefined") v.path = data.path;
                        if(typeof(data.pname) != "undefined") v.pname = data.pname;
                        if(typeof(data.query) != "undefined") v.query = data.query;
                        if(typeof(data.refs) != "undefined") v.refs = data.refs;
                        if(typeof(data.request) != "undefined") v.request = data.request;
                        if(typeof(data.response) != "undefined") v.response = data.response;
                        if(typeof(data.resolution) != "undefined") v.resolution = data.resolution;
                        if(typeof(data.website) != "undefined") v.website = data.website;
                    }
            
/*
                    statusReportFact.putVulns($scope.workspace, v, function(rev, evidence) {
                        v.rev = rev;
                        v.attachments = evidence;
                    });
*/
                    v.selected = false;
                }
                $scope.vulns.push(v);
            });
        };

        // action triggered from DELETE button
        $scope.delete = function() {
            selected = getSelectedVulns($scope.vulns, true);

            if(selected.length > 0) {
                var modal = $modal.open({
                    templateUrl: 'scripts/commons/partials/modalDelete.html',
                    controller: 'commonsModalDelete',
                    size: 'lg',
                    resolve: {
                        msg: function() {
                            var msg = "";
                            if(selected.length == 1) {
                                msg = "A vulnerability will be deleted.";
                            } else {
                                msg = selected.length + " vulnerabilities will be deleted.";
                            }
                            msg += " This action cannot be undone. Are you sure you want to proceed?";
                            return msg;
                        }
                    }
                });

                modal.result.then(function() {
                    $scope.remove(selected);
                });
            } else {
                var modal = $modal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'No vulnerabilities were selected to delete';
                        }
                    }
                });
            }
        };

        // action triggered from EDIT button
        $scope.edit = function() {
            var selected = false;

            $scope.vulns.forEach(function(v) {
                if(v.selected) selected = true;
            });

            if(selected) {
                var modal = $modal.open({
                    templateUrl: 'scripts/statusReport/partials/modalEdit.html',
                    controller: 'modalEditCtrl',
                    size: 'lg',
                    resolve: {
                        severities: function() {
                            return $scope.severities;
                        },
                        vulns: function() {
                            return $scope.vulns;
                        }
                    }
                });

                modal.result.then(function(data) {
                    $scope.update(data);
                });
            } else {
                var modal = $modal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'At least one vulnerabilty must be selected in order to edit';
                        }
                    }
                });
            }
        };

        $scope.insert = function(vuln) {
            vulnsManager.createVuln($scope.workspace, vuln).then(function() {
                console.log("success");
                $scope.vulns.push(vuln);
            }, function(e) {
                console.error(e);
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
                    controller: 'modalNewCtrl',
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
                v.selected = $scope.selectall;
            });
        };

        $scope.calculateNumberOfPages = function() {
            if($scope.vulns.length <= 10) {
                $scope.showPagination = 0;
            } else {
                $scope.showPagination = 1;
            }
            return parseInt($scope.vulns.length/$scope.pageSize);
        };

        $scope.go = function() {
            if($scope.go_page < $scope.numberOfPages+1 && $scope.go_page > -1) {
                $scope.currentPage = $scope.go_page;
            }
            $scope.pageSize = $scope.pagination;
            if($scope.go_page > $scope.numberOfPages) {
                $scope.currentPage = 0;
            }
            $cookies.pageSize = $scope.pageSize;
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
                        encode += "&" + prop + "=" + chunks[prop];
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
                decode[param.slice(0,i)] = param.slice(i+1);
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

        init();
    }]);
