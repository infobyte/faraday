// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('licensesManager',
        ['License', 'BASEURL', 'configSrv', '$http', '$q',
        function(License, BASEURL, configSrv, $http, $q) {
        var licensesManager = {};

        licensesManager.licenses = [];

        licensesManager.products = [
            "Faraday",
            "Metasploit",
            "Nessus",
            "Acunetix",
            "Burp",
            "Canvas",
            "Maltego",
            "Core Impact",
            "Nexpose",
            "Netsparker",
            "Retina",
            "Onapsis Security Platform",
            "Qualys",
            "Fortify",
            "Checkmarx",
            "Other"
        ];

        licensesManager.DBExists = function() {
            var deferred = $q.defer(),
            self = this;

            configSrv.promise
                .then(function() {
                    var url = BASEURL + configSrv.license_db;

                    $http.head(url)
                        .then(function(resp) {
                            // status 200 - DB exists!
                            deferred.resolve(true);
                        }, function(resp) {
                            // status 404 - DB doesn't exist
                            deferred.resolve(false);
                        });
                }, function() {
                    deferred.reject("Unable to fetch licenses database name.");
                });

            return deferred.promise;
        };

        licensesManager.createDB = function() {
            var deferred = $q.defer(),
            self = this;

            configSrv.promise
                .then(function() {
                    var url = BASEURL + configSrv.license_db;

                    $http.put(url)
                        .then(function(resp) {
                            deferred.resolve(true);
                        }, function(resp) {
                            deferred.reject(resp);
                        });
                }, function() {
                    deferred.reject("Unable to fetch licenses database name.");
                });

            return deferred.promise;
        };

        licensesManager.create = function(data) {
            var deferred = $q.defer(),
            self = this;

            try {
                var license = new License(data);

                license.save()
                    .then(function(resp) {
                        licensesManager.get()
                            .then(function() {
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
        };

        licensesManager.delete = function(license) {
            var deferred = $q.defer(),
            self = this;

            license.remove()
                .then(function() {
                    licensesManager.get()
                        .then(function(resp) {
                            deferred.resolve(resp);
                        }, function(reason) {
                            deferred.reject(reason);
                        });
                }, function(err) {
                    deferred.reject(err);
                });

            return deferred.promise
        };

        licensesManager.get = function() {
            var deferred = $q.defer(),
            self = this;

            configSrv.promise
                .then(function() {
                    var url = BASEURL + configSrv.license_db + "/_all_docs?include_docs=true";

                    $http.get(url)
                        .then(function(res) {
                            var data = res.data;
                            var licenses = [];

                            if(data.hasOwnProperty("rows")) {
                                data.rows.forEach(function(row) {
                                    try {
                                        licenses.push(new License(row.doc));
                                    } catch(e) {
                                        console.log(e.stack);
                                    }
                                });
                            }

                            angular.copy(licenses, self.licenses);
                            deferred.resolve(licenses);
                        }, function(data, status, headers, config) {
                            deferred.reject("Unable to retrieve Licenses. " + status);
                        });
                });

            return deferred.promise;
        };

        licensesManager.update = function(license, data) {
            var deferred = $q.defer(),
            self = this;

            license.update(data)
                .then(function() {
                    licensesManager.get()
                        .then(function(resp) {
                            deferred.resolve(resp);
                        }, function(reason) {
                            deferred.reject(reason);
                        });
                }, function(err) {
                    deferred.reject(err);
                });

            return deferred.promise;
        };

        return licensesManager;
    }]);
