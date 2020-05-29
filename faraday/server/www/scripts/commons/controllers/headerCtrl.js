// Faraday Penetration Test IDE
// Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('headerCtrl', [
        '$scope',
        '$routeParams',
        '$location',
        '$cookies',
        'dashboardSrv',
        'workspacesFact',
        'vulnsManager',
        '$uibModal',
        function ($scope,
                  $routeParams,
                  $location,
                  $cookies,
                  dashboardSrv,
                  workspacesFact,
                  vulnsManager,
                  $uibModal) {

            $scope.confirmed = ($cookies.get('confirmed') == undefined) ? false : JSON.parse($cookies.get('confirmed'));
            $scope.confirmed ? $cookies.put('filterConfirmed', "Confirmed"): $cookies.put('filterConfirmed', "All");

            $scope.showSwitcher = function() {
                var noSwitcher = [
                    "", "home", "login", "index", "workspaces", "users", "licenses",
                    "taskgroup", "executive", // Only for white versions!!
                    "vulndb", "comparison", "webshell", "help", "forbidden", "data_analysis"
                ];
                return noSwitcher.indexOf($scope.component) < 0;
            };

            // Ugly, ugly, ugly hack
            $scope.vulnsNum = vulnsManager.getVulnsNum($routeParams.wsId);
            $scope.totalVulns = vulnsManager.getTotalVulns($routeParams.wsId);
            $scope.logo_url = "images/logo-faraday-blanco.svg";
            setInterval(function(){
                $scope.vulnsNum = vulnsManager.getVulnsNum($routeParams.wsId);
                $scope.totalVulns = vulnsManager.getTotalVulns($routeParams.wsId);
                $scope.$apply();
            }, 500)

            $scope.toggleConfirmed = function() {
                $scope.confirmed = !$scope.confirmed;
                dashboardSrv.setConfirmed($scope.confirmed);
                dashboardSrv.updateData();
            };

            $scope.updateWorkspace = function(ws, wsName, finally_){
                if(typeof(ws.duration.start_date) == "number") {
                    start_date = ws.duration.start_date;
                } else if(ws.duration.start_date) {
                    start_date = ws.duration.start_date.getTime();
                } else {start_date = "";}
                if(typeof(ws.duration.end_date) == "number") {
                    end_date = ws.duration.end_date;
                } else if(ws.duration.end_date) {
                    end_date = ws.duration.end_date.getTime();
                } else {end_date = "";}
                duration = {'start_date': start_date, 'end_date': end_date};
                workspace = {
                    "_id":          ws._id,
                    "_rev":         ws._rev,
                    "children":     ws.children,
                    "customer":     ws.customer,
                    "description":  ws.description,
                    "duration":     duration,
                    "name":         ws.name,
                    "scope":        ws.scope,
                    "type":         ws.type
                };
                workspacesFact.update(workspace, wsName).then(function(workspace) {
                    if (finally_) finally_(workspace);
                    $location.path($scope.location + "/ws/" + workspace.name);
                }, function(error){
                    if (finally_) finally_(workspace);
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        resolve: {
                            msg: function() {
                                if (error.status == 409){
                                    return "A workspace with that name already exists";
                                }
                                return error;
                            }
                        }
                    });
                });
            };

            $scope.editWorkspace = function() {
                if($scope.workspace !== undefined) {
                    var workspace;
                    var index = -1;
                    $scope.workspaces.forEach(function(w, i) {
                        if(w.name === $scope.workspace) {
                            workspace = w;
                            index = i;
                        }
                    });

                    // copy pasted from server/www/scripts/workspaces/controllers/workspaces.js
                    // it makes scope work properly (i think)
                    workspace.scope = workspace.scope.map(function(scope){
                        if(scope.key === undefined)
                            return {key: scope};
                        return scope;
                    });
                    if (workspace.scope.length == 0) workspace.scope.push({key: ''});

                    var oldName = $scope.workspace;
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/workspaces/partials/modalEdit.html',
                        backdrop : 'static',
                        controller: 'workspacesModalEdit',
                        size: 'lg',
                        resolve: {
                            ws: function() {
                                return workspace;
                            }
                        }
                    });

                    modal.result.then(function(workspace) {
                        // The API expects list of strings in scope
                        // var old_scope = workspace.scope;
                        workspace.scope = workspace.scope.map(function(scope){
                            return scope.key;
                        }).filter(Boolean);

                        $scope.updateWorkspace(workspace, oldName, function(workspace){
                            // workspace.scope = old_scope;
                            $scope.workspaces[index] = angular.copy(workspace);
                        });
                    });
                }
            };

            getWorkspaces = function() {
                workspacesFact.getWorkspaces().then(function(wss) {
                    // $scope.workspacesNames = [];
                    $scope.workspaces = [];

                    wss.forEach(function(ws){
                        // $scope.workspacesNames.push(ws.name);
                        $scope.workspaces.push(ws);
                    });
                });
            };

            init = function(name) {
                $scope.location = $location.path().split('/')[1];
                $scope.workspace = $routeParams.wsId;
                if($routeParams.wsId)
                    vulnsManager.loadVulnsCounter($routeParams.wsId);

                getWorkspaces();

            };

            init();
    }]);
