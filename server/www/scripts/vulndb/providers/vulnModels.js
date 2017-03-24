// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
//
angular.module('faradayApp').
    factory('vulnModelsManager', 
        ['VulnModel', 'BASEURL', 'configSrv', '$http', '$q',
            function(VulnModel, BASEURL, configSrv, $http, $q) {
                var vulnModelsManager = {};
                vulnModelsManager.pageSize = 20
                vulnModelsManager.models = [];
                vulnModelsManager.totalNumberOfModels 
                vulnModelsManager.totalNumberOfPages

                vulnModelsManager.DBExists = function() {
                    var deferred = $q.defer();
                    var self = this;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB;

                            $http.head(url).
                                then(function(resp) {
                                    deferred.resolve(true);
                                }, function(resp) {
                                    deferred.resolve(false);
                                });
                        }, function() {
                            deferred.reject("Unable to fetch the Vulnerability Models DB name.");
                        });

                    return deferred.promise;
                };

                vulnModelsManager.createDB = function() {
                    var deferred = $q.defer();
                    var self = this;

                    configSrv.promise
                        .then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB;

                            $http.put(url).
                                then(function(resp) {
                                    deferred.resolve(true);
                                }, function(resp) {
                                    deferred.reject(resp);
                                });
                        }, function() {
                            deferred.reject("Unable to fetch Vulnerability Model DB name.");
                        });

                    return deferred.promise;
                };

                vulnModelsManager.create = function(data) {
                    var deferred = $q.defer();
                    var self = this;

                    try {
                        var vulnModel = new VulnModel(data);
                        vulnModel.save().
                            then(function(resp) {
                                vulnModelsManager.get().
                                    then(function() {
                                        self.updateState(self.totalNumberOfModels + 1)
                                        deferred.resolve(self);
                                    }, function(reason) {
                                        deferred.reject(reason);
                                    });
                            }, function(reason) {
                                deferred.reject(reason);
                            });
                    } catch(e) {
                        deferred.reject(e.name + ": " + e.message);
                    }

                    return deferred.promise;
                }

                vulnModelsManager.delete = function(vulnModel) {
                    var deferred = $q.defer();
                    var self = this;

                    vulnModel.remove().
                        then(function() {
                            vulnModelsManager.get().
                                then(function(resp) {
                                    self.updateState(self.totalNumberOfModels - 1)
                                    deferred.resolve(resp);
                                }, function(reason) {
                                    deferred.reject(reason);
                                });
                        }, function(err) {
                            deferred.reject(err);
                        });
                    return deferred.promise;
                };

                vulnModelsManager.get = function(page, all) {
                    var deferred = $q.defer();
                    var self = this;
                    if (all === undefined) { all = false)

                    configSrv.promise.
                        then(function() {
                            var skip;
                            if (page) { skip = (page - 1) * self.pageSize } else { skip = 0 }
                            var url = BASEURL + configSrv.vulnModelsDB + "/_all_docs?include_docs=true&limit=" + self.pageSize + "&skip=" + skip;
                            if (all) { url = BASEURL + configSrv.vulnModelsDB + "_all_docs?include_docs=true" }

                            $http.get(url).
                                then(function(res) {
                                    var data = res.data;

                                    var vulnModels = []

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
                        });

                    return deferred.promise;
                };

                vulnModelsManager.getSize = function() {
                    var deferred = $q.defer();
                    var self = this;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB + "/_all_docs"
                            $http.get(url).
                                then(function(res) {
                                    var data = res.data;
                                    console.log("TOTAL ROWS: " + data.total_rows)
                                    self.updateState(data.total_rows)
                                    deferred.resolve()
                                }, function(data, status) {
                                    deferred.reject("Unable to retrieve documents " + status)
                                })
                        })
                    return deferred.promise;
                }

                vulnModelsManager.updateState = function(numberOfModels) {
                    this.totalNumberOfModels = numberOfModels
                    this.totalNumberOfPages = Math.ceil(this.totalNumberOfModels / this.pageSize)
                }


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
