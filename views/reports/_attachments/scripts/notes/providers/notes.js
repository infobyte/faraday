// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('notesFact', ['BASEURL', '$http', function(BASEURL, $http) {
        var notesFact = {};

        notesFact.getNotes = function(ws, parent) {
            var noteIds = [];
            var notes = [];
            var note = {};
            var params = JSON.stringify([parent, "Note"]);
            var url = BASEURL + ws + "/_design/mapper/_view/byparentandtype?key=" + params;
            $.getJSON(url, function(data) {
                $.each(data.rows, function(n, obj) {
                    noteIds.push(obj.value);
                });
            });
            noteIds.forEach(function(id) {
                url = BASEURL + ws + "/" + id;
                $.getJSON(url, function(data) {
                    note = {
                        "id":   data._id,
                        "rev":  data._rev,
                        "name": data.name,
                        "text": data.text
                    };
                    notes.push(note);
                });
            });
            return notes;
        };

        // updates note if existing, creates otherwise
        notesFact.putNote = function(ws, name, parent, text) {
            var notes   = notesFact.getNotes(ws, parent);
            var note    = {};
            var exists  = false;
            var url     = BASEURL + ws + "/";
            var id      = "";
            var rev     = "";

            // we need to check the name fits before updating
            if(notes.length) {
                notes.forEach(function(note) {
                    if(note.name === name) {
                        id      = note.id;
                        rev     = note.rev;
                        url     += note.id;
                        exists  = true;
                    }
                });
            }

            if(!exists) {
                // insert
                id = parent + "." + CryptoJS.SHA1("Message").toString();
                url += id;
                note = {
                    "name":     name,
                    "parent":   parent,
                    "owned":    false,
                    "text":     text,
                    "type":     "Note"
                };
            } else {
                // update
                note = {
                    "_id":      id,
                    "_rev":     rev,
                    "name":     name,
                    "parent":   parent,
                    "owned":    false,
                    "text":     text,
                    "type":     "Note"
                };
            }

            $http.put(url, note);
        };

        return notesFact;
    }]);
