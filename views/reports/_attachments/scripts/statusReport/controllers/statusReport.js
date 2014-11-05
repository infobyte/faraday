angular.module('faradayApp')
    .controller('statusReportCtrl', 
                    ['$scope', '$filter', '$route', '$routeParams', '$modal', '$log', 'statusReportFact', 
                    function($scope, $filter, $route, $routeParams, $modal, $log, statusReportFact) {
        $scope.$log = $log;
        $scope.sortField = 'date';
        $scope.reverse = true;
        // load all workspaces
        statusReportFact.getWorkspaces(function(wss) {
            $scope.workspaces = wss;
        });
        // current workspace
        $scope.workspace = $routeParams.wsId;
        // load all vulnerabilities
        $scope.vulns = statusReportFact.getVulns($scope.workspace);

        // toggles column show property
        $scope.toggleShow = function(column, show) {
            $scope.columns[column] = !show;
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
        }
        
        // set columns to show and hide by default
        $scope.columns = {
            "data":     true,
            "date":     true,
            "desc":     true,
            "method":   false,
            "name":     true,
            "params":   false,
            "path":     false,
            "pname":    false,
            "query":    false,
            "request":  false,
            "response": false,
            "severity": true,
            "status":   true,
            "target":   true,
            "web":      true,
            "website":  false
        };

        $scope.severities = [
            "unclassified",
            "info",
            "low",
            "med",
            "high"
        ];

        // returns scope vulns as CSV obj
        $scope.toCSV = function() {
            var method      = "";
            var website     = "";
            var desc        = "";
            var text        = "";
            var path        = "";
            var pname       = "";
            var params      = "";
            var query       = "";
            var request     = "";
            var response    = "";

            var content = "\"Date\", \"Web\", \"Status\", \"Severity\", "+
                "\"Name\", \"Target\", \"Description\", "+
                "\"Data\", \"Method\", \"Path\", \"Param Name\", \"Params\", "+
                "\"Query\", \"Request\", \"Response\", \"Website\" \n";
            
            $scope.vulns.forEach(function(v) {
                method      = "";
                website     = "";
                desc        = "";
                text        = "";
                path        = "";
                pname       = "";
                params      = "";
                query       = "";
                request     = "";
                response    = "";

                if(typeof(v.desc) != "undefined")   desc    = v.desc.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                if(typeof(v.data) != "undefined")   text    = v.data.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                if(v.type === "VulnerabilityWeb") {
                    if(typeof(v.method) != "undefined")     method      = v.method;
                    if(typeof(v.website) != "undefined")    website     = v.website;
                    if(typeof(v.path) != "undefined")       path        = v.path.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                    if(typeof(v.pname) != "undefined")      pname       = v.pname.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                    if(typeof(v.params) != "undefined")     params      = v.params.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                    if(typeof(v.query) != "undefined")      query       = v.query.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                    if(typeof(v.request) != "undefined")    request     = v.request.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
                    if(typeof(v.response) != "undefined")   response    = v.response.replace(/\n[ ]*\n/g, "").replace(/\"/g, "'");
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
                    " \""+request+"\","+
                    " \""+response+"\","+
                    " \""+website+"\""+
                    "\n";
            });

            var obj = {
                "title":    "SR-" + $scope.workspace,
                "content":  content
            };
            
            return obj;
        };

        // deletes all vulns with selected == true
        $scope.remove = function() {
            var old = $scope.vulns;
            $scope.vulns = [];

            old.forEach(function(v) {
                if(v.selected) {
                    statusReportFact.removeVulns($scope.workspace, v);
                } else {
                    $scope.vulns.push(v);
                }
            });
        };

        // updates all vulns with selected == true
        $scope.update = function(data) {
            $scope.vulns = [];
            
            data.vulns.forEach(function(v) {
                if(v.selected) {
                    if(typeof(data.severity) == "string") v.severity = data.severity;
                    if(typeof(data.name) != "undefined") v.name = data.name;
                    if(typeof(data.desc) != "undefined") v.desc = data.desc;
                    if(typeof(data.data) != "undefined") v.data = data.data;
                    if(v.web) {
                        if(typeof(data.method) != "undefined") v.method = data.method;
                        if(typeof(data.params) != "undefined") v.params = data.params;
                        if(typeof(data.path) != "undefined") v.path = data.path;
                        if(typeof(data.pname) != "undefined") v.pname = data.pname;
                        if(typeof(data.query) != "undefined") v.query = data.query;
                        if(typeof(data.request) != "undefined") v.request = data.request;
                        if(typeof(data.response) != "undefined") v.response = data.response;
                        if(typeof(data.website) != "undefined") v.website = data.website;
                    }
            
                    statusReportFact.putVulns($scope.workspace, v, function(rev) {
                        v.rev = rev;
                    });
                    v.selected = false;
                }
                $scope.vulns.push(v);
            });
        };

        // action triggered from DELETE button
        $scope.delete = function() {
            var selected = false;
            var i = 0;

            $scope.vulns.forEach(function(v) {
                if(v.selected) {
                    selected = true;
                    i++;
                }
            });

            if(selected) {
                var modal = $modal.open({
                    templateUrl: 'scripts/partials/modal-delete.html',
                    controller: 'modalDeleteCtrl',
                    size: 'lg',
                    resolve: {
                        amount: function() {
                            return i;
                        }
                    }
                });

                modal.result.then(function() {
                    $scope.remove();
                });
            } else {
                var modal = $modal.open({
                    templateUrl: 'scripts/partials/modal-ko.html',
                    controller: 'modalKoCtrl',
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
                    templateUrl: 'scripts/partials/modal-edit.html',
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
                    templateUrl: 'scripts/partials/modal-ko.html',
                    controller: 'modalKoCtrl',
                    resolve: {
                        msg: function() {
                            return 'At least one vulnerabilty must be selected in order to edit';
                        }
                    }
                });
            }
        };

        $scope.checkAll = function() {
            if(!$scope.selectall) {
                $scope.selectall = true;
            } else {
                $scope.selectall = false;
            }

            angular.forEach($filter('filter')($scope.vulns, $scope.query), function(v) {
                v.selected = $scope.selectall;
            });
        };
    }]);
