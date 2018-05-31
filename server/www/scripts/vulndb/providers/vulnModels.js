// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
//
angular.module('faradayApp').
    factory('vulnModelsManager',
        ['VulnModel', 'BASEURL', '$http', '$q', 'ServerAPI',
            function(VulnModel, BASEURL, $http, $q, ServerAPI) {
                var vulnModelsManager = {};
                vulnModelsManager.models = [];
                vulnModelsManager.totalNumberOfModels = 0;

                vulnModelsManager.create = function(data, outsider) {
                    if (outsider === undefined) { var outsider = false; };
                    var deferred = $q.defer();
                    var self = this;

                    try {
                        var vulnModel = new VulnModel(data);
                        vulnModel.save()
                            .then(function(resp) {
                                if (outsider) {
                                    deferred.resolve(resp);
                                } else {
                                    vulnModelsManager.get()
                                        .then(function() {
                                            self.updateState(self.totalNumberOfModels + 1);
                                            deferred.resolve(self);
                                        }, function(reason) {
                                            deferred.reject(reason);
                                        });
                                }}, function(reason) {
                                deferred.reject(reason);
                            });
                    } catch(e) {
                        deferred.reject(e.name + ": " + e.message);
                    }

                    return deferred.promise;
                };

                vulnModelsManager.delete = function(vulnModel) {
                    var deferred = $q.defer();
                    var self = this;

                    vulnModel.remove().
                        then(function() {
                            vulnModelsManager.get().
                                then(function(resp) {
                                    self.updateState(self.totalNumberOfModels - 1);
                                    deferred.resolve(resp);
                                }, function(reason) {
                                    deferred.reject(reason);
                                });
                        }, function(err) {
                            deferred.reject(err);
                        });
                    return deferred.promise;
                };

                vulnModelsManager.get = function() {
                    var deferred = $q.defer();
                    var self = this;

                    ServerAPI.getVulnerabilityTemplates()
                        .then(function(res) {
                            var data = res.data;
                            var vulnModels = [];

                            if (data.hasOwnProperty("rows")) {
                                data.rows.forEach(function(row) {
                                    try {
                                        vulnModels.push(new VulnModel(row.doc));
                                    } catch(e) {
                                        console.log(e.stack);
                                    }
                                });
                            }

                            angular.copy(vulnModels, self.models);
                            deferred.resolve(vulnModels);
                        }, function(data, status, headers, config) {
                            deferred.reject("Unable to retrieve vuln models. " + status);
                        });

                    return deferred.promise;
                };

                vulnModelsManager.getSize = function() {
                    var deferred = $q.defer();
                    var self = this;

                    ServerAPI.getVulnerabilityTemplates()
                        .then(function(res) {
                            var data = res.data;
                            self.updateState(data.total_rows);
                            deferred.resolve();
                        }, function(data, status) {
                            deferred.reject("Unable to retrieve documents " + status);
                        });
                    return deferred.promise;
                };

                vulnModelsManager.updateState = function(numberOfModels) {
                    this.totalNumberOfModels = numberOfModels;
                };


                vulnModelsManager.update = function(vulnModel, data) {
                    var deferred = $q.defer();
                    var self = this;

                    if (data._rev === undefined) {
                        data._rev = vulnModel._rev;
                    }

                    vulnModel.update(data).
                        then(function() {
                            vulnModelsManager.get().
                                then(function(resp) {
                                    deferred.resolve(resp);
                                }, function(reason) {
                                    deferred.reject(reason);
                                });
                        }, function(err) {
                            deferred.reject(err);
                        });

                    return deferred.promise;
                };

                return vulnModelsManager;
            }]);
