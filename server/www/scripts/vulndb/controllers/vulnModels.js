angular.module('faradayApp')
    .controller('vulnModelsCtrl',
        ['$scope', '$filter', '$http', '$q', '$uibModal', 'ServerAPI', 'csvService', 'commonsFact', 'vulnModelsManager',
            function($scope, $filter, $http, $q, $uibModal, ServerAPI, csvService, commonsFact, vulnModelsManager) {
                $scope.db_exists = false;
                $scope.models = [];
                $scope.loaded_models = false;
                $scope.reverse;
                $scope.search;
                console.log(ServerAPI);

                var init = function() {
                    // table stuff
                    $scope.selectall_models = false;
                    $scope.sort_field = "end";
                    $scope.reverse = true;

                    vulnModelsManager.DBExists()
                        .then(function(exists) {
                            if (!exists) {
                                $uibModal.open({
                                    templateUrl: 'scripts/vulndb/partials/modalCreateDB.html',
                                    controller: 'vulndbModalCreateDB',
                                    size: 'lg'
                                }).result.then(function(data) {
                                    if (data) {
                                        $scope.db_exists = true;
                                        console.log($uibModal);

                                    }
                                }, function(message) { 
                                    // no db created, do nothing!

                                });
                            } else {
                                $scope.db_exists = true;
                                vulnModelsManager.get(0)
                                    .then(function() {
                                        $scope.models = vulnModelsManager.models;
                                        $scope.loaded_models = true;
                                    });
                            }
                        }, function(message) {
                            commonsFact.errorDialog(message);
                        });

                    $scope.$watch(function() {
                        return vulnModelsManager.models;
                    }, function(newVal, oldVal) {
                        $scope.models = vulnModelsManager.models;
                        $scope.loaded_models = true;
                    }, true);
                };

                $scope.remove = function(ids) {
                    var confirmations = [];

                    ids.forEach(function(id) {
                        var deferred = $q.defer();

                        vulnModelsManager.delete(id)
                            .then(function(resp) {
                                deferred.resolve(resp);
                            }, function(message) {
                                deferred.reject(message);
                            });

                        confirmations.push(deferred);
                    });

                    return $q.all(confirmations);
                };

                $scope.importCSV = function() {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/vulndb/partials/upload.html',
                        controller: 'vulnModelModalUpload',
                        size: 'sm',
                        resolve: { }
                    });

                    modal.result.then(
                        function(data) {
                            Papa.parse(data, {
                                worker: true,
                                header: true,
                                skipEmptyLines: true,
                                step: function(results) {
                                    if (results.data) {
                                        $scope.insert(results.data[0])
                                    }
                                }
                            });
                        });
                };

                $scope.importFromWorkspace = function() {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/vulndb/partials/importFromWs.html',
                        controller: 'vulnModelModalImportFromWs',
                        size: 'sm',
                        resolve: { }
                    });

                    modal.result.then(function(data) {
                        ServerAPI.getVulns(data).then(function(vulns_data) {
                            var vulns = vulns_data.data.vulnerabilities
                            var relevant_data_of_vulns = [];
                            vulns.forEach(function(vuln) {
                                relevant_vuln = {};
                                relevant_vuln.name = vuln.value.name;
                                relevant_vuln.description = vuln.value.description;
                                relevant_vuln.resolution = vuln.value.resolution;
                                relevant_data_of_vulns.push(relevant_vuln);
                            });
                            console.log(relevant_data_of_vulns);
                            relevant_data_of_vulns.forEach(function(relevant_vuln) {
                                $scope.insert(relevant_vuln);
                            });
                        })
                    })
                }

                $scope.delete = function() {
                    var selected = $scope.selectedModels();
                    console.log("HERE");
                    console.log(selected);

                    if(selected.length == 0) {
                        $uibModal.open({
                            templateUrl: 'scripts/commons/partials/modalKO.html',
                            controller: 'commonsModalKoCtrl',
                            size: 'sm',
                            resolve: {
                                msg: function() {
                                    return 'No models were selected to delete';
                                }
                            }
                        });
                    } else {
                        var message = "A vulnerability model will be deleted";
                        if(selected.length > 1) {
                            message = selected.length  + " vulnerability models will be deleted";

                        }
                        message = message.concat(". This operation cannot be undone. Are you sure you want to proceed?");
                        $uibModal.open({
                            templateUrl: 'scripts/commons/partials/modalDelete.html',
                            controller: 'commonsModalDelete',
                            size: 'lg',
                            resolve: {
                                msg: function() {
                                    return message;
                                }
                            }
                        }).result.then(function() {
                            $scope.remove(selected);
                        }, function() {
                            //dismised, do nothing
                        });
                    }
                };

                $scope.insert = function(data) {
                    vulnModelsManager.create(data)
                        .catch(function(message) {
                            commonsFact.errorDialog(message);
                        });
                };

                $scope.new = function() {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/vulndb/partials/modalNew.html',
                        controller: 'vulnModelModalNew',
                        size: 'lg',
                        resolve: {}
                    });

                    modal.result
                        .then(function(data) {
                            $scope.insert(data);
                        });
                };

                $scope.update = function(model, data) {
                    vulnModelsManager.update(model, data)
                        .catch(function(message) {
                            commonsFact.errorDialog(message);
                        });
                };

                $scope.edit = function() {
                    if($scope.selectedModels().length == 1) {
                        var model = $scope.selectedModels()[0];
                        var modal = $uibModal.open({
                            templateUrl: 'scripts/vulndb/partials/modalEdit.html',
                            controller: 'vulndDbModalEdit',
                            size: 'lg',
                            resolve: {
                                model: function() {
                                    return model;
                                }
                            }
                        });

                        modal.result.then(function(data) {
                            $scope.update(model, data);
                        });
                    } else {
                        commonsFact.errorDialog("No Vulnerability Models were selected to edit.");
                    }
                };

                $scope.selectedModels = function() {
                    var selected = [];

                    $filter('filter')($scope.models, $scope.search).forEach(function(model) {
                        if(model.selected === true) {
                            selected.push(model);
                        }
                    });

                    return selected;
                };

                $scope.checkAll = function() {
                    $scope.selectall_models = !$scope.selectall_models;

                    tmp_models = $filter('filter')($scope.models, $scope.search);
                    tmp_models.forEach(function(model) {
                        model.selected = $scope.selectall_models;
                    });
                };

                // changes the URL according to search params
                $scope.searchFor = function(search, params) {
                    // TODO: It would be nice to find a way for changing
                    // the url without reloading the controller
                    if(search && params != "" && params != undefined) {
                        var filter = commonsFact.parseSearchExpression(params);
                        var URLParams = commonsFact.searchFilterToURLParams(filter);
                        url += "/search/" + URLParams;
                    }

                    $location.path(url);
                };


                // toggles sort field and order
                $scope.toggleSort = function(field) {
                    $scope.toggleSortField(field);
                    $scope.toggleReverse();
                };

                // toggles column sort field
                $scope.toggleSortField = function(field) {
                    $scope.sort_field = field;
                };

                // toggle column sort order
                $scope.toggleReverse = function() {
                    $scope.reverse = !$scope.reverse;
                }

                init();
            }]);


