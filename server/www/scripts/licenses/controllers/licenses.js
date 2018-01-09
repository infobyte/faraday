// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .controller('licensesCtrl',
        ['$scope', '$filter', '$q', '$uibModal', 'commonsFact', 'licensesManager',
        function($scope, $filter, $q, $uibModal, commonsFact, licensesManager) {

            $scope.expiration_month = false;
            $scope.licenses = [];
            $scope.loaded_licenses = false;
            $scope.reverse;
            $scope.search;
            $scope.selectall_licenses;
            $scope.sort_field;
            $scope.store;

            var init = function() {
                $scope.store = "https://appstore.faradaysec.com/search/?q=";

                // table stuff
                $scope.selectall_licenses = false;
                $scope.sort_field = "end";
                $scope.reverse = true;

                licensesManager.get()
                    .then(function() {
                        $scope.licenses = licensesManager.licenses;
                        $scope.loaded_licenses = true;

                        $scope.expiration_month = $scope.isExpirationMonth($scope.licenses);
                    }, function(message) {
                        commonsFact.errorDialog(message);
                    });

                $scope.$watch(function() {
                    return licensesManager.licenses;
                }, function(newVal, oldVal) {
                    $scope.licenses = licensesManager.licenses;
                    $scope.loaded_licenses = true;
                    $scope.expiration_month = $scope.isExpirationMonth(newVal);
                }, true);
            };

            $scope.almostExpired = function(end) {
                var end_date = new Date(end),
                today = new Date();
                return (end_date.getMonth() == today.getMonth()) && (end_date.getYear() == today.getYear());
            };

            $scope.isExpirationMonth = function(licenses) {
                return licenses.some(function(elem, index, array) {
                    return $scope.almostExpired(elem.end);
                });
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
                    $uibModal.open({
                        templateUrl: 'scripts/commons/partials/modalKO.html',
                        controller: 'commonsModalKoCtrl',
                        size: 'sm',
                        resolve: {
                            msg: function() {
                                return 'No licenses were selected to delete';
                            }
                        }
                    });
                } else {
                    var message = "A license will be deleted";
                    if(selected.length > 1) {
                        message = selected.length  + " licenses will be deleted";
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

                $filter('filter')($scope.licenses, $scope.search).forEach(function(license) {
                    if(license.selected === true) {
                        selected.push(license);
                    }
                });

                return selected;
            };

            $scope.checkAll = function() {
                $scope.selectall_licenses = !$scope.selectall_licenses;

                tmp_licenses = $filter('filter')($scope.licenses, $scope.search);
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
                $scope.sort_field = field;
            };

            // toggle column sort order
            $scope.toggleReverse = function() {
                $scope.reverse = !$scope.reverse;
            }

            init();
    }]);
