// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('licensesManager',
        ['License', 'APIURL', '$http', '$q',
        function(License, APIURL, $http, $q) {
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

            var url = APIURL + "licenses/";

            $http.get(url)
                .then(function(res) {
                    var licenses = [];
                    res.data.forEach(function(row) {
                        try {
                            var new_lic = new License(row);
                            licenses.push(new_lic);
                        } catch(e) {
                            console.log(e.stack);
                        }
                    });

                    angular.copy(licenses, self.licenses);
                    deferred.resolve(licenses);
                }, function(data, status, headers, config) {
                    deferred.reject("Unable to retrieve Licenses. " + status);
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
