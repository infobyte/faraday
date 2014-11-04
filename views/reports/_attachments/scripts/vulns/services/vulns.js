angular.module('faradayApp')
    .factory('vulnsFact', ['BASEURL', '$http', 'notesFact', function(BASEURL, $http, notesFact) {
        var vulnsFact = {};

        vulnsFact.get = function(ws) {
            var vulns = [];
            var note = {};
            vulns_url = BASEURL + ws +"/_design/vulns/_view/vulns";
            // gets vulns json from couch
            $.getJSON(vulns_url, function(data) {
                $.each(data.rows, function(n, obj){
                    var d = new Date(0); 
                    d.setUTCSeconds(obj.value.date);
                    d = d.getDate() + "/" + d.getMonth() + "/" + d.getFullYear();
                    var notes = notesFact.getNotes(ws, obj.id);
                    notes.forEach(function(n) {
                        if(n.name === "data") note = n;
                    });
                    var v = {
                        "id":           obj.id,
                        "rev":          obj.value.rev,
                        "desc":         obj.value.desc,
                        "data":         note,
                        "meta":         obj.value.meta,
                        "date":         d, 
                        "name":         obj.value.name, 
                        "oid":          obj.value.oid,
                        "owned":        obj.value.owned,
                        "owner":        obj.value.owner,
                        "parent":       obj.key.substring(0, obj.key.indexOf('.')),
                        "couch_parent": obj.value.parent,
                        "refs":         obj.value.refs,
                        "severity":     obj.value.severity,
                        "type":         obj.value.type, 
                        "web":          false,
                        "selected":     false,
                        "delete":       false
                    };
                    vulns.push(v);
                });
            });
            return vulns;
        }

        vulnsFact.put = function(ws, vuln, callback) {
            var url = BASEURL + ws + "/" + vuln.id;
            var v = {
                "_rev":         vuln.rev,
                "desc":         vuln.desc, 
                "metadata":     vuln.meta,
                "name":         vuln.name, 
                "obj_id":       vuln.oid,
                "owned":        vuln.owned,
                "owner":        vuln.owner,
                "parent":       vuln.couch_parent, 
                "refs":         vuln.refs,
                "severity":     vuln.severity, 
                "type":         vuln.type
            };
            $http.put(url, v).success(function(d, s, h, c) {
                callback(d.rev);
                console.log(vuln); 
                notesFact.putNote(ws, "data", vuln.id, vuln.data.text);
            });
        };

        vulnsFact.remove = function(ws, vuln) {
            var url = BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev;
            $http.delete(url).success(function(d, s, h, c) {
                console.log(d);
            });
        };

        return vulnsFact;
    }]);
