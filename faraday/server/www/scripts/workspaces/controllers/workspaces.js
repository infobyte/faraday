// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('workspacesCtrl', ['$uibModal', '$scope', '$q', 'workspacesFact', 'dashboardSrv', '$location', '$cookies',
        function ($uibModal, $scope, $q, workspacesFact, dashboardSrv, $location, $cookies) {
            $scope.hash;
            $scope.objects;
            $scope.workspaces;
            $scope.wss;
            $scope.search;

            $scope.init = function () {
                $scope.objects = [];
                $scope.workspaces = [];
                $scope.wss = [];
                $scope.archived = false;
                // $scope.newworkspace = {};

                var hash_tmp = window.location.hash.split("/")[1];
                switch (hash_tmp) {
                    case "status":
                        $scope.hash = "status";
                        break;
                    case "dashboard":
                        $scope.hash = "dashboard";
                        break;
                    case "hosts":
                        $scope.hash = "hosts";
                        break;
                    default:
                        $scope.hash = "";
                }

                workspacesFact.getWorkspaces().then(function (wss) {

                    $scope.wss = []; // Store workspace names
                    wss.forEach(function (ws) {
                        $scope.wss.push(ws.name);
                        $scope.onSuccessGet(ws);
                        $scope.objects[ws.name] = {
                            "total_vulns": "-",
                            "hosts": "-",
                            "services": "-"
                        };
                        for (var stat in ws.stats) {
                            if (ws.stats.hasOwnProperty(stat)) {
                                if ($scope.objects[ws.name].hasOwnProperty(stat))
                                    $scope.objects[ws.name][stat] = ws.stats[stat];
                            }
                        }
                        ;
                    });
                });
            };

            $scope.onSuccessGet = function (workspace) {
                workspace.selected = false;
                workspace.scope = workspace.scope.map(function (scope) {
                    return {key: scope}
                });
                if (workspace.scope.length == 0) workspace.scope.push({key: ''});
                $scope.workspaces.push(workspace);
            };

            $scope.onSuccessInsert = function (workspace) {
                $scope.wss.push(workspace.name);
                workspace.scope = workspace.scope.map(function (scope) {
                    return {key: scope}
                });
                if (workspace.scope.length == 0) workspace.scope.push({key: ''});

                $scope.objects[workspace.name] = workspace.stats;

                // Ulgy hack to keep the workspaces sorted alphabetically
                for (var i = 0; i < $scope.workspaces.length; i++) {
                    if ($scope.workspaces[i].name > workspace.name) break;
                }
                $scope.workspaces.splice(i, 0, workspace);
            };

            $scope.onFailInsert = function (error) {
                var modal = $uibModal.open({
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    resolve: {
                        msg: function () {
                            if (error.status == 409) {
                                return "A workspace with that name already exists"
                            }
                            return error.data.message;
                        }
                    }
                });
            };

            $scope.onSuccessEdit = function (workspace) {
                for (var i = 0; i < $scope.workspaces.length; i++) {
                    if ($scope.workspaces[i]._id == workspace._id) {
                        $scope.workspaces[i].name = workspace.name;
                        $scope.workspaces[i]._rev = workspace._rev;
                        $scope.workspaces[i].description = workspace.description;
                        if ($scope.workspaces[i].duration === undefined)
                            $scope.workspaces[i].duration = {};
                        $scope.workspaces[i].duration.start_date = workspace.duration.start_date;
                        $scope.workspaces[i].duration.end_date = workspace.duration.end_date;
                        $scope.workspaces[i].scope = workspace.scope;
                        break;
                    }
                }
                ;
            };

            $scope.onSuccessDelete = function (workspace_name) {
                remove = function (arr, item) {
                    for (var i = arr.length; i--;) {
                        if (arr[i] === item) {
                            arr.splice(i, 1);
                        }
                    }
                    return arr;
                };

                $scope.wss = remove($scope.wss, workspace_name);
                for (var i = 0; i < $scope.workspaces.length; i++) {
                    if ($scope.workspaces[i].name == workspace_name) {
                        $scope.workspaces.splice(i, 1);
                        break;
                    }
                }
                ;
            };

            $scope.insert = function (workspace) {
                delete workspace.selected;
                workspacesFact.put(workspace).then(function (resp) {
                        workspace.active = resp.data.active;
                        workspace.stats = resp.data.stats;
                        $scope.onSuccessInsert(workspace)
                    },
                    $scope.onFailInsert);
            };

            $scope.update = function (ws, wsName, finally_) {
                if (typeof(ws.duration.start_date) == "number") {
                    start_date = ws.duration.start_date;
                } else if (ws.duration.start_date) {
                    start_date = ws.duration.start_date.getTime();
                } else {
                    start_date = "";
                }
                if (typeof(ws.duration.end_date) == "number") {
                    end_date = ws.duration.end_date;
                } else if (ws.duration.end_date) {
                    end_date = ws.duration.end_date.getTime();
                } else {
                    end_date = "";
                }
                duration = {'start_date': start_date, 'end_date': end_date};
                workspace = {
                    "_id": ws._id,
                    "_rev": ws._rev,
                    "children": ws.children,
                    "customer": ws.customer,
                    "description": ws.description,
                    "duration": duration,
                    "name": ws.name,
                    "scope": ws.scope,
                    "type": ws.type
                };
                workspacesFact.update(workspace, wsName).then(function (workspace) {
                    if (finally_) finally_(workspace);
                    $scope.onSuccessEdit(workspace);
                }, function (error) {
                    if (finally_) finally_(workspace);
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        resolve: {
                            msg: function () {
                                if (error.status == 409) {
                                    return "A workspace with that name already exists"
                                }
                                return error;
                            }
                        }
                    });
                });
            };

            $scope.remove = function (workspace_name) {
                workspacesFact.delete(workspace_name).then(function (resp) {
                    $scope.onSuccessDelete(resp);
                });
            };

            // Modals methods
            $scope.new = function () {
                $scope.modal = $uibModal.open({
                    templateUrl: 'scripts/workspaces/partials/modalNew.html',
                    backdrop: 'static',
                    controller: 'workspacesModalNew',
                    size: 'lg'
                });

                $scope.modal.result.then(function (workspace) {
                    // The API expects list of strings in scope
                    api_scope = workspace.scope.map(function (scope) {
                        return scope.key
                    }).filter(Boolean);

                    workspace = $scope.create(workspace.name, workspace.description, workspace.start_date, workspace.end_date, api_scope);
                    $scope.insert(workspace);
                });

            };

            $scope.edit = function () {
                var workspace;

                $scope.workspaces.forEach(function (w) {
                    if (w.selected) {
                        workspace = w;
                    }
                });

                if (workspace) {
                    var oldName = workspace.name;
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/workspaces/partials/modalEdit.html',
                        backdrop: 'static',
                        controller: 'workspacesModalEdit',
                        size: 'lg',
                        resolve: {
                            ws: function () {
                                return workspace;
                            }
                        }
                    });

                    modal.result.then(function (workspace) {
                        // The API expects list of strings in scope
                        var old_scope = workspace.scope;
                        workspace.scope = workspace.scope.map(function (scope) {
                            return scope.key
                        }).filter(Boolean);

                        $scope.update(workspace, oldName, function (workspace) {
                            workspace.scope = old_scope;
                        });
                    });
                } else {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        resolve: {
                            msg: function () {
                                return 'No workspaces were selected to edit';
                            }
                        }
                    });
                }

            };

            $scope.delete = function () {
                var selected = false;

                $scope.workspaces.forEach(function (w) {
                    if (w.selected) {
                        selected = true;
                        return;
                    }
                });

                if (selected) {
                    $scope.modal = $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalDelete.html',
                        controller: 'commonsModalDelete',
                        size: 'lg',
                        resolve: {
                            msg: function () {
                                var msg = "A workspace will be deleted. This action cannot be undone. Are you sure you want to proceed?";
                                return msg;
                            }
                        }
                    });

                    $scope.modal.result.then(function () {
                        $scope.workspaces.forEach(function (w) {
                            if (w.selected == true)
                                $scope.remove(w.name);
                        });
                    });
                } else {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        resolve: {
                            msg: function () {
                                return 'No workspaces were selected to delete';
                            }
                        }
                    });
                }
            };
            // This is in the modal context only
            $scope.okDelete = function () {
                $scope.modal.close();
            };
            // end of modal context

            $scope.create = function (wname, wdesc, start_date, end_date, scope) {
                if (end_date) end_date = end_date.getTime(); else end_date = "";
                if (start_date) start_date = start_date.getTime(); else start_date = "";
                var workspace = {
                    "_id": wname,
                    "customer": "",
                    "name": wname,
                    "type": "Workspace",
                    "children": [],
                    "duration": {"start_date": start_date, "end_date": end_date},
                    "scope": scope,
                    "description": wdesc
                };
                return (workspace);

            };

            $scope.redirect = function (path) {
                $location.path("/" + ($location.path().split('/')[1] || 'dashboard') + "/ws/" + path);
            };
            $scope.dashboardRedirect = function (path) {
                $location.path("/dashboard/ws/" + path);
            };

            $scope.clearSearch = function () {
                $scope.search = '';
            };

            $scope.activeToggle = function (ws) {
                if (ws.active) {
                    workspacesFact.deactivate(ws.name).then(function (resp) {
                        if (resp.data) {
                            ws.active = false;

                            let pos = -1;
                            if ($cookies.get('currentUrl') !== undefined)
                                pos = $cookies.get('currentUrl').indexOf('ws/');

                            if (pos >= 0) {
                                let savedWs = $cookies.get('currentUrl').slice(pos + 3);
                                if (ws.name === savedWs){
                                    $cookies.remove('currentUrl');
                                    workspacesFact.changeWorkspace(null);
                                }

                            }
                        }
                    });
                } else {
                    workspacesFact.activate(ws.name).then(function (resp) {
                        if (resp.data) {
                            ws.active = true
                        }
                    });
                }
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


        $scope.clearSearch = function() {
          $scope.search = '';
        };

         $scope.readonlyToggle = function (ws) {
            workspacesFact.readOnlyToogle(ws.name).then(function (resp) {
                ws.readonly = resp.data;
            });
        };

            $scope.init();
        }]);
