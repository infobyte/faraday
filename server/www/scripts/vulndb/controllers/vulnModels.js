angular.module('faradayApp')
    .controller('vulnModelsCtrl',
        ['$scope', '$filter', '$http', '$q', '$uibModal', 'csvService', 'commonsFact', 'vulnModelsManager',
        function($scope, $filter, $http, $q, $uibModal, csvService, commonsFact, vulnModelsManager) {
            $scope.db_exists = false;
            $scope.models = [];
            $scope.loaded_models = false;
            $scope.reverse;
            $scope.search;

            var init = function() {
                // table stuff
                $scope.selectall_models = false;
                $scope.sort_field = "end";
                $scope.reverse = true;

                vulnModelsManager.DBExists()
                    .then(function(exists) {
                        if(!exists) {
                            $uibModal.open({
                                templateUrl: 'scripts/vulndb/partials/modalCreateDB.html',
                                controller: 'vulndbModalCreateDB',
                                size: 'lg'
                            }).result.then(function() {
                                $scope.db_exists = true;
                            }, function(message) { });
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

            $scope.csv = function() {
                deferred = $q.defer();
                var model_properties = {
                    'name': true,
                    'cwe': true,
                    'references': true,
                    'resolution': true,
                    'desc_summary': true,
                    'exploitation': true,
                };
                vulnModelsManager.get().then(function(response) {
                    deferred.resolve(csvService.generator(model_properties, response.models, null)
                )});
                return deferred.promise;
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
                        controller: 'modelsModalEdit',
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

            
