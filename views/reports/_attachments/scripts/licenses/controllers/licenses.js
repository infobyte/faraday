// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesCtrl',
        ['$scope', '$cookies', '$filter', '$location', '$q', '$route', '$routeParams', '$uibModal', 'commonsFact', 'licensesManager',
        function($scope, $cookies, $filter, $location, $q, $route, $routeParams, $uibModal, commonsFact, licensesManager) {

            $scope.currentPage;
            $scope.expression;
            $scope.licenses = [];
            $scope.newCurrentPage;
            $scope.newPageSize;
            $scope.pageSize;
            $scope.reverse;
            $scope.search;
            $scope.searchParams;
            $scope.selectall_licenses;
            $scope.sortField;
            $scope.store;

        init = function() {
            $scope.store = "http://ts557851-container.zoeysite.com/";

            // table stuff
            $scope.selectall_licenses = false;
            $scope.sortField = "end";
            $scope.reverse = true;

            // pagination stuff
            $scope.pageSize = 100;
            $scope.currentPage = 0;
            $scope.newCurrentPage = 0;
            if(!isNaN(parseInt($cookies.pageSize))) $scope.pageSize = parseInt($cookies.pageSize);
            $scope.newPageSize = $scope.pageSize;

            // current search
            $scope.search = $routeParams.search;
            $scope.searchParams = "";
            $scope.expression = {};
            if($scope.search != "" && $scope.search != undefined && $scope.search.indexOf("=") > -1) {
                // search expression for filter
                $scope.expression = commonsFact.decodeSearch($scope.search);
                // search params for search field, which shouldn't be used for filtering
                $scope.searchParams = commonsFact.stringSearch($scope.expression);
            }

            licensesManager.get()
                .then(function() {
                    $scope.licenses = licensesManager.licenses;
                });
        };

        // changes the URL according to search params
        $scope.searchFor = function(search, params) {
            var url = "/licenses";

            if(search && params != "" && params != undefined) {
                url += "/search/" + commonsFact.encodeSearch(params);
            }

            $location.path(url);
        };

        $scope.go = function() {
            $scope.pageSize = $scope.newPageSize;
            $cookies.pageSize = $scope.pageSize;
            $scope.currentPage = 0;
            if($scope.newCurrentPage <= parseInt($scope.licenses.length/$scope.pageSize)
                    && $scope.newCurrentPage > -1 && !isNaN(parseInt($scope.newCurrentPage))) {
                $scope.currentPage = $scope.newCurrentPage;
            }
        };

        $scope.remove = function(ids) {
            var confirmations = [];

            ids.forEach(function(id) {
                var deferred = $q.defer();

                licensesManager.delete(id, $scope.workspace)
                    .then(function(resp) {
                        deferred.resolve(resp);
                    }, function(message) {
                        deferred.reject(message);
                    });

                confirmations.push(deferred);
            });

            return $q.all(confirmations);
        };

        $scope.delete = function() {
            var selected = $scope.selectedLicenses();

            if(selected.length == 0) {
                $uibModal.open(config = {
                    templateUrl: 'scripts/commons/partials/modalKO.html',
                    controller: 'commonsModalKoCtrl',
                    size: 'sm',
                    resolve: {
                        msg: function() {
                            return 'No licenses were selected to delete';
                        }
                    }
                })
            } else {
                var message = "A license will be deleted";
                if(selected.length > 1) {
                    message = selected.length  + " licenses will be deleted";
                }
                message = message.concat(". This operation cannot be undone. Are you sure you want to proceed?");
                $uibModal.open(config = {
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
            licensesManager.create(data)
                .catch(function(message) {
                    commonsFact.errorDialog(message);
                });
        };

        $scope.new = function() {
            var modal = $uibModal.open({
                templateUrl: 'scripts/licenses/partials/modalNew.html',
                controller: 'licensesModalNew',
                size: 'lg',
                resolve: {}
             });

            modal.result
                .then(function(data) {
                    $scope.insert(data);
                });
        };

        $scope.update = function(license, data) {
            licensesManager.update(license, data)
                .catch(function(message) {
                    commonsFact.errorDialog(message);
                });
        };

        $scope.edit = function() {
            if($scope.selectedLicenses().length == 1) {
                var license = $scope.selectedLicenses()[0];
                var modal = $uibModal.open({
                    templateUrl: 'scripts/licenses/partials/modalEdit.html',
                    controller: 'licensesModalEdit',
                    size: 'lg',
                    resolve: {
                        license: function() {
                            return license;
                        }
                    }
                 });

                modal.result.then(function(data) {
                    $scope.update(license, data);
                });
            } else {
                commonsFact.errorDialog("No licenses were selected to edit.");
            }
        };

        $scope.selectedLicenses = function() {
            var selected = [];

            $scope.filter($scope.licenses).forEach(function(license) {
                if(license.selected === true) {
                    selected.push(license);
                }
            });

            return selected;
        };

        $scope.checkAll = function() {
            $scope.selectall_licenses = !$scope.selectall_licenses;

            tmp_licenses = $scope.filter($scope.licenses);
            tmp_licenses.forEach(function(license) {
                license.selected = $scope.selectall_licenses;
            });
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

        $scope.filter = function(data) {
            var tmp_data = $filter('orderBy')(data, $scope.sortField, $scope.reverse);
            tmp_data = $filter('filter')(tmp_data, $scope.expression);
            tmp_data = tmp_data.splice($scope.pageSize * $scope.currentPage, $scope.pageSize);

            return tmp_data;
        };

        init();
    }]);
