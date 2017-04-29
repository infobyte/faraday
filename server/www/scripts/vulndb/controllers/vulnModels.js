angular.module('faradayApp')
    .controller('vulnModelsCtrl',
        ['$scope', '$filter', '$http', '$q', '$uibModal', 'ServerAPI', 'csvService', 'commonsFact', 'vulnModelsManager',
            function($scope, $filter, $http, $q, $uibModal, ServerAPI, csvService, commonsFact, vulnModelsManager) {
                $scope.db_exists = false;
                $scope.models = [];
                $scope.loaded_models = false;
                $scope.totalModels = 0;
                $scope.disabledClick = false;
                $scope.reverse;
                $scope.search;
                $scope.currentPage;

                var init = function() {
                    // table stuff
                    $scope.selectall_models = false;
                    $scope.sort_field = "end";
                    $scope.reverse = true;
                    $scope.currentPage = 1;

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
                                    }
                                }, function(message) { 
                                    // no db created, do nothing!
                                });
                            } else {
                                $scope.db_exists = true;
                                vulnModelsManager.get()
                                    .then(function() {
                                        $scope.models = vulnModelsManager.models;
                                        $scope.loaded_models = true;
                                    });
                                vulnModelsManager.getSize().
                                    then(function() {
                                        $scope.totalModels = vulnModelsManager.totalNumberOfModels
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

                $scope.pageCount = function() {
                    return vulnModelsManager.totalNumberOfPages;
                };

                $scope.prevPageDisabled = function() {
                    return $scope.currentPage <= 1;
                };

                $scope.nextPageDisabled = function() {
                    return $scope.currentPage >= $scope.pageCount();
                };

                $scope.nextPage = function() {
                    if ($scope.currentPagepage <= 0 || $scope.currentPage > $scope.pageCount) { return; }
                    $scope.currentPage += 1;
                    vulnModelsManager.get($scope.currentPage);
                };

                $scope.prevPage = function() {
                    if ($scope.currentPagepage <= 0 || $scope.currentPage > $scope.pageCount) { return; }
                    $scope.currentPage -= 1;
                    vulnModelsManager.get($scope.currentPage);
                };


                $scope.go = function() {
                    var page = $scope.newCurrentPage;
                    if (page <= 0 || page > $scope.pageCount || ! page) { return; }
                    $scope.currentPage = page;
                    vulnModelsManager.get($scope.currentPage);
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
                        size: 'lg',
                        resolve: { }
                    });

                    var datas = [];
                    modal.result.then(
                        function(data) {
                            document.body.style.cursor='wait';
                            $scope.disabledClick = true;
                            Papa.parse(data, {
                                worker: true,
                                header: true,
                                skipEmptyLines: true,
                                step: function(results) {
                                    if (results.data) {datas.push(results.data[0]);}
                                },
                                complete: function(res, file) {
                                    // i feel dirty, really, but it works.
                                    // pro tip: 'complete' only means it has completed 'parsing'
                                    // not completed doing whatever is defined on step
                                    var length = datas.length;
                                    var counter = 0;
                                    datas.forEach(function(data) {
                                        $scope.insert(data).then(function() {
                                            counter = counter + 1;
                                            if (length == counter) {
                                                document.body.style.cursor = "default";
                                                $scope.disabledClick = false;
                                            }
                                        });
                                    });
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
                        document.body.style.cursor='wait';
                        ServerAPI.getVulns(data).then(
                            function(vulns_data) {
                                $scope.disabledClick = true;
                                var vulns = vulns_data.data.vulnerabilities;
                                vulns.forEach(function(vuln) {
                                    relevant_vuln = {};
                                    relevant_vuln.name = vuln.value.name;
                                    relevant_vuln.description = vuln.value.dec_summary;
                                    relevant_vuln.resolution = vuln.value.resolution;
                                    relevant_vuln.exploitation = vuln.value.severity;
                                    relevant_vuln.references = vuln.value.references;
                                    $scope.insert(relevant_vuln);
                                });
                            }).then(function() {
                                document.body.style.cursor = "default";
                                $scope.disabledClick = false;
                            });
                        });
                };

                $scope.delete = function() {
                    var selected = $scope.selectedModels();

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
                    return vulnModelsManager.create(data)
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


