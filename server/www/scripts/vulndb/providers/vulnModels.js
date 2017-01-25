// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
//
angular.module('faradayApp').
    factory('vulnModelsManager', 
        ['vulnModel', 'BASEURL', 'configSrv', '$http', '$q',
            function(vulnModel, BASEURL, configSrv, $http, $q) {
                var vulnModelsManager = {};

                vulnModelsManager.models = [];

                vulnModelsManager.DBExists = function() {
                    var deferred = $q.defer();
                    self = this;

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

                    console.log("HERE2")
                    return deferred.promise;
                };

                vulnModelsManager.createDB = function() {
                    var deferred = $q.defer();
                    self = this;

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
                    self = this;

                    try {
                        var vulnModel = new vulnModel(data);

                        vulnModel.save().
                            then(function(resp) {
                                vulnModelsManager.get().
                                    then(function() {
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
                    self = this;

                    vulnModel.remove().
                        then(function() {
                            vulnModel.get().
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

                vulnModelsManager.get = function() {
                    var deferred = $q.defer();
                    self = this;

                    configSrv.promise.
                        then(function() {
                            var url = BASEURL + configSrv.vulnModelsDB + "/_all_docs?include_docs=true";

                            $http.get(url).
                                then(function(res) {
                                    var data = res.data;
                                    var vulnModels = [];

                                    if (data.hasOwnProperty("rows")) {
                                        data.rows.forEach(function(row) {
                                            try {
                                                vulnModels.push(new vulnModel(row.doc));
                                            } catch(e) {
                                                console.log(e.stack);
                                            }
                                        });
                                    }

                                    angular.copy(vulnModels, self.vulnModels);
                                    deferred.resolve(vulnModels);
                                }, function(data, status, headers, config) {
                                    deferred.reject("Unable to retrieve vuln models. " + status);
                                });
                        });

                    return deferred.promise;
                };

                vulnModelsManager.update = function(vulnModel, data) {
                    var deferred = $q.defer();
                    self = this;

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
