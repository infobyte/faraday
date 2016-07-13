// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('License', ['BASEURL', 'configSrv', '$http', '$q',
    function(BASEURL, configSrv, $http, $q) {
        License = function(data) {
            var now = new Date(),
            date = now.getTime() / 1000.0;

            this._id = "";
            this._rev = "";
            this.end = "";
            this.lictype = "";
            this.metadata = {
                update_time: date,
                update_user: "",
                update_action: 0,
                creator: "UI Web",
                create_time: date,
                update_controller_action: "UI Web New",
                owner: ""
            };
            this.notes = "";
            this.product = "";
            this.start = "";
            this.type = "License";

            if(data) {
                if(data.product === undefined || data.product === "") {
                    throw new Error("Unable to create License without a product name");
                }
                this.set(data);
            }
        };

        License.prototype = {
            public_properties: [
                'end', 'lictype', 'notes', 'product', 'start'
            ],
            set: function(data) {
                var self = this;

                // new license
                if(data._id != undefined) {
                    self._id = data._id;
                    if(data._rev !== undefined) self._rev = data._rev;
                    if(data.metadata !== undefined) self.metadata = data.metadata;
                }

                self.public_properties.forEach(function(property) {
                    if(data[property] !== undefined) self[property] = data[property];
                });
            },
            remove: function() {
                var deferred = $q.defer(),
                self = this;

                configSrv.promise
                    .then(function() {
                        var url = BASEURL + configSrv.license_db + "/" + self._id + "?rev=" + self._rev;

                        $http.delete(url)
                            .then(function(resp) {
                                deferred.resolve(resp);
                            }, function(data, status, headers, config) {
                                deferred.reject("Unable to delete License from database. " + status);
                            });
                    }, function(reason) {
                        deferred.reject(reason);
                    });

                return deferred.promise;
            },
            update: function(data) {
                var deferred = $q.defer(),
                self = this;

                configSrv.promise
                    .then(function() {
                        var url = BASEURL + configSrv.license_db;

                        $http.put(url, self)
                            .then(function(data) {
                                self._rev = data.rev;
                                deferred.resolve(self);
                            }, function(data, status, headers, config) {
                                deferred.reject("Unable to update the License. " + status);
                            });
                    }, function(reason) {
                        deferred.reject(reason);
                    });

                return deferred.promise;
            },
            save: function() {
                var deferred = $q.defer(),
                self = this;

                configSrv.promise
                    .then(function() {
                        var url = BASEURL + configSrv.license_db;

                        $http.post(url, self)
                            .then(function(data) {
                                self._rev = data.rev;
                                deferred.resolve(self);
                            }, function(data, status, headers, config) {
                                deferred.reject("Unable to save the License. " + status);
                            });
                    }, function(reason) {
                        deferred.reject(reason);
                    });

                return deferred.promise;
            }
        };

        return License;
    }]);
