// Faraday Penetration Test IDE
// Copyright (C) 2017  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

"use strict";

angular.module('faradayApp')
    .factory('credential', ['ServerAPI',
    function(ServerAPI) {

        // All credentials need this properties minimum.
        var _credentialFields = {
            '_id': 'string',
            'name': 'string',
            'username': 'string',
            'password': 'string',
            'type': 'string'
        };

        Credential = function(data){
            if(data) {
                this.set(data);
            }
        };

        //TODO: Build ID with parent
        Credential.prototype = {
            set: function(data) {

                data.type = "Cred";
                if(data._id === undefined)
                    data['_id'] = _generateID(data.name, data.username, data.password);
                
                _checkFieldsOk(data);
                angular.extend(this, data);
            },

            delete: function(ws) {
                return ServerAPI.deleteCredential(ws, this._id, this._rev);
            },

            update: function(ws, data) {
                var self = this;
                
                return ServerAPI.updateCredential(ws, data)
                .then(function(credentialData) {
                    self._rev = credentialData.rev;
                });
            },

            save: function(ws) {
                var self = this;

                return ServerAPI.createHost(ws, self).
                    then(function(credential_data) {
                        self._rev = credential_data.rev;
                    });
            }
        }

    var _generateID = function(name, username, password){
        var id = CryptoJS.SHA1([name, username, password].join('._.')).toString();
        return id;
    };

    // Check object to construct have all fields and also, type of they are OK.
    // All fields in _credentialFields should are in object.
    var _checkFieldsOk = function(credential){

        Object.keys(_credentialFields).forEach(function(key, index) {
            // Credential dont have property or type of property in credential dont same.
            if(!credential.hasOwnProperty(key) || typeof(credential.key) !== _credentialFields.key)
               throw 'Credential-Invalid fields: Invalid fields in credential creation: ' + key;
        });
    };
    return Credential;
}]);