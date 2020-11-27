angular.module('faradayApp')
    .controller('vulnModelsCtrl', [
        '$scope',
        '$filter',
        '$http',
        '$q',
        '$uibModal',
        'ServerAPI',
        'csvService',
        'commonsFact',
        'vulnModelsManager',
        'APIURL',
        '$route',
        'BASEURL',
        function ($scope,
                  $filter,
                  $http,
                  $q,
                  $uibModal,
                  ServerAPI,
                  csvService,
                  commonsFact,
                  vulnModelsManager,
                  APIURL,
                  $route,
                  BASEURL) {

                $scope.models = [];
                $scope.loaded_models = false;
                $scope.totalModels = 0;
                $scope.disabledClick = false;
                $scope.reverse;
                $scope.search = '';
                $scope.currentPage;
                $scope.pageSize = 20;
                $scope.loading = false;
                $scope.customFields;

                var init = function() {
                    // table stuff
                    $scope.selectall_models = false;
                    $scope.sort_field = "name";
                    $scope.reverse = true;
                    $scope.currentPage = 1;
                    $scope.loading = true;
                    vulnModelsManager.get()
                        .then(function() {
                            $scope.loading = false;
                            $scope.totalModels = vulnModelsManager.totalNumberOfModels;
                            $scope.models = vulnModelsManager.models;
                            $scope.loaded_models = true;
                        });

                    $scope.$watch(function() {
                        return vulnModelsManager.models;
                    }, function(newVal, oldVal) {
                        $scope.models = vulnModelsManager.models;
                        $scope.loaded_models = true;
                    }, true);
                    $scope.$watch(function() {
                        return $scope.pageCount();
                    }, function(newVal, oldVal, scope) {
                        if ($scope.currentPage > $scope.pageCount()) {
                            $scope.currentPage = $scope.pageCount();
                        }
                    });;

                    loadCustomFields();
                };

                var loadCustomFields = function () {
                    var deferred = $q.defer();
                    ServerAPI.getCustomFields().then(
                        function(response){
                            $scope.customFields = response.data;
                            deferred.resolve($scope.customFields);
                        }, function(){
                            deferred.reject();
                        });
                };

                $scope.pageCount = function() {
                    // if the guy searched for something with exactly 0 results, there's just '1' page;
                    // the one she's seeing with zero results
                    var searchPages = $scope.pagesOnSearch();

                    if (searchPages === undefined) {
                        return (Math.ceil(vulnModelsManager.totalNumberOfModels / this.pageSize) || 1);
                    } else {
                        // if searchpages is zero, pretend like its one
                        return (searchPages || 1);
                    }
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
                };

                $scope.prevPage = function() {
                    if ($scope.currentPagepage <= 0 || $scope.currentPage > $scope.pageCount) { return; }
                    $scope.currentPage -= 1;
                };


                $scope.go = function() {
                    var page = $scope.newCurrentPage;
                    if (page <= 0 || page > $scope.pageCount || ! page) { return; }
                    $scope.currentPage = page;
                };


                $scope.remove = function(ids) {
                    var confirmations = [];

                    ids.forEach(function(id) {
                        var deferred = $q.defer();

                        var promise = vulnModelsManager.delete(id)
                            .then(function(resp) {
                                deferred.resolve(resp);
                            }, function(message) {
                                deferred.reject(message);
                            });

                        confirmations.push(promise);
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

                    var loadCSV = function(data) {

                        $http.get(BASEURL + '_api/session').then(
                            function(d) {
                              $scope.csrf_token = d.data.csrf_token;

                              var fd = new FormData();
                              fd.append('csrf_token', $scope.csrf_token);
                              fd.append('file', data);

                              $scope.loading = true;

                              $http.post(APIURL + 'vulnerability_template/bulk_create/', fd, {
                                transformRequest: angular.identity,
                                withCredentials: false,
                                headers: {'Content-Type': undefined}
                                }).then(
                                    function(d) {
                                        $scope.loading = false;
                                        var message = "Vulnerability templates created:\n";
                                        d.data.vulns_created.forEach(function(vuln) {
                                            message += "\t" + vuln[1] + "\n";
                                        });

                                        message += "\n\n";
                                        message += loadCSVErrorMessage(d.data);

                                        commonsFact.showMessage(message, true);
                                        $route.reload();
                                    },
                                    function(d){
                                        $scope.loading = false;
                                        var message = "Error uploading vulnerability templates.\n\n";
                                        if(d.status === 400 && d.data.message)
                                            message += d.data.message;
                                        else
                                            message += loadCSVErrorMessage(d.data)
                                        commonsFact.showMessage(message);
                                    }
                                );
                            }
                          );
                    };

                    var loadCSVErrorMessage = function(data) {
                        var message = "";
                        if(data.vulns_with_conflict.length > 0) {
                            message += "Vulnerability templates that were " +
                                       "not created due to conflict error:\n";
                            data.vulns_with_conflict.forEach(function(vuln) {
                                message += "\t" + vuln[1] + "\n";
                            });
                        }
                        message += "\n\n";

                        if(data.vulns_with_errors.length > 0) {
                            message += "Vulnerability templates that were " +
                                       "not create due to an error:\n";
                            data.vulns_with_errors.forEach(function(vuln) {
                                message += "\t" + vuln[1] + "\n";
                            });
                        }

                        return message;
                    };

                    modal.result.then(function(data) {
                        document.body.style.cursor='wait';
                        $scope.disabledClick = true;
                        var reader = new FileReader();
                        reader.readAsText(data);
                        reader.onload = function(e) {
                            loadCSV(data);
                        };
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
                            $scope.remove(selected).then(function(){

                                vulnModelsManager.get().then(function() {
                                    $scope.totalModels = vulnModelsManager.totalNumberOfModels;
                                    $scope.models = vulnModelsManager.models;
                                });
                            });
                        }, function() {
                            //dismised, do nothing
                        });
                    }
                };

                $scope.insert = function(data) {
                    $scope.loading = false;

                    return vulnModelsManager.create(data)
                        .then(function(data) {
                            $scope.loading = false;
                        })
                        .catch(function(message) {
                            $scope.loading = false;
                            commonsFact.errorDialog(message);
                        });
                };

                $scope.new = function() {
                    var modal = $uibModal.open({
                        templateUrl: 'scripts/vulndb/partials/modalNew.html',
                        backdrop : 'static',
                        controller: 'vulnModelModalNew',
                        size: 'lg',
                        resolve: {
                                customFields: function () {
                                return $scope.customFields;
                            }
                        }
                    });

                    modal.result
                        .then(function(data) {
                            $scope.insert(data).then(function() {

                                vulnModelsManager.get().then(function() {
                                    $scope.totalModels = vulnModelsManager.totalNumberOfModels;
                                    $scope.models = vulnModelsManager.models;
                                });
                            });
                        });
                };

                $scope.update = function(model, data) {
                    return vulnModelsManager.update(model, data)
                        .catch(function(message) {
                            commonsFact.errorDialog(message);
                        });
                };

                $scope.edit = function() {
                    if($scope.selectedModels().length == 1) {
                        var model = $scope.selectedModels()[0];
                        var modal = $uibModal.open({
                            templateUrl: 'scripts/vulndb/partials/modalEdit.html',
                            backdrop : 'static',
                            controller: 'vulndDbModalEdit',
                            size: 'lg',
                            resolve: {
                                model: function() {
                                    return model;
                                },customFields: function () {
                                    return $scope.customFields;
                                }
                            }
                        });

                        modal.result.then(function(data) {
                            $scope.update(model, data).then(function() {

                                vulnModelsManager.get().then(function() {
                                    $scope.totalModels = vulnModelsManager.totalNumberOfModels;
                                    $scope.models = vulnModelsManager.models;
                                });

                            });
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

                $scope.pagesOnSearch = function() {
                    var number = $scope.howManyInSearch();
                    if (number === undefined) { return undefined; }
                    return Math.ceil(number / 20);
                };

                $scope.howManyInSearch = function() {
                    if (! $scope.search) { return undefined; }   // if nothing is searched, there's nothing there
                    var filteredModels = $filter('filter')($scope.models, $scope.search);
                    return filteredModels.length;
                };

                $scope.checkAll = function() {
                    $scope.selectall_models = !$scope.selectall_models;

                    tmp_models = $filter('filter')($scope.models, $scope.search);
                    tmp_models = $filter('orderBy')(tmp_models, $scope.sort_field, $scope.reverse);
                    tmp_models = tmp_models.slice(this.currentPage * this.pageSize-20, this.currentPage * this.pageSize);
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
                };

                $scope.clearSearch = function() {
                  $scope.search = '';
                };

                var equalAsSets = function(a, b) {
                    if(a.length != b.length) return false;

                    a.forEach(function(elem) {
                        if(b.indexOf(elem) == -1) return false
                    });

                    b.forEach(function(elem) {
                        if(a.indexOf(elem) == -1) return false
                    });

                    return true;
                };

                init();
            }]);

//We already have a limitTo filter built-in to angular,
//let's make a startFrom filter
angular.module('faradayApp').filter('startFrom', function() {
    return function(input, start) {
        start = +start; //parse to int
        return input.slice(start);
    };
});
