angular.module('faradayApp')
    .factory('vulnsWebFact', ['BASEURL', '$http', 'attachmentsFact', function(BASEURL, $http, attachmentsFact) {
        var vulnsWebFact = {};

        vulnsWebFact.get = function(ws) {
            var vulns = [];
            vulns_url = BASEURL + ws +"/_design/vulns/_view/web";
            // gets vulns json from couch
            $.getJSON(vulns_url, function(data) {
                $.each(data.rows, function(n, obj){
                    var d = new Date(0);
                    d.setUTCSeconds(obj.value.date);
                    d = d.getDate() + "/" + (d.getMonth() + 1) + "/" + d.getFullYear();
                    var v = {
                        "id":           obj.id,
                        "rev":          obj.value.rev,
                        "couch_parent": obj.value.parent,
                        "data":         obj.value.data,
                        "date":         d, 
                        "delete":       false,
                        "desc":         obj.value.desc, 
                        "meta":         obj.value.meta,
                        "name":         obj.value.name, 
                        "oid":          obj.value.oid,
                        "owned":        obj.value.owned,
                        "owner":        obj.value.owner,
                        "parent":       obj.key.substring(0, obj.key.indexOf('.')),
                        "refs":         obj.value.refs,
                        "selected":     false,
                        "severity":     obj.value.severity,
                        "type":         obj.value.type, 
                        "web":          true,
                        /*** specific fields of web vulns ***/
                        "method":       obj.value.method,
                        "params":       obj.value.params,
                        "path":         obj.value.path,
                        "pname":        obj.value.pname,
                        "query":        obj.value.query,
                        "request":      obj.value.request,
                        "response":     obj.value.response,
                        "website":      obj.value.website
                    };
                    vulns.push(v);
                });
            });
            return vulns;
        }

        vulnsWebFact.put = function(ws, vuln, callback) {
            var url = BASEURL + ws + "/" + vuln.id;
            var v = {
                "_rev":         vuln.rev,
                "data":         vuln.data,
                "desc":         vuln.desc, 
                "metadata":     vuln.meta,
                "name":         vuln.name, 
                "obj_id":       vuln.oid,
                "owned":        vuln.owned,
                "owner":        vuln.owner,
                "parent":       vuln.couch_parent, 
                "refs":         vuln.refs,
                "severity":     vuln.severity, 
                "type":         vuln.type,
                /*** specific fields of web vulns ***/
                "method":       vuln.method,
                "params":       vuln.params,
                "path":         vuln.path,
                "pname":        vuln.pname,
                "query":        vuln.query,
                "request":      vuln.request,
                "response":     vuln.response,
                "website":      vuln.website
            };
            if(typeof(vuln.evidence) != undefined && vuln.evidence != undefined) {
                attachmentsFact.loadAttachments(vuln.evidence).then(function(result) {
                    var attachments = {};
                    result.forEach(function(attachment) {
                        attachments[attachment.filename] = attachment.value;
                    });
                    
                    v._attachments = attachments;
                    $http.put(url, v).success(function(d, s, h, c) {
                        callback(d.rev);
                    });
                });
            } else {
                $http.put(url, v).success(function(d, s, h, c) {
                    callback(d.rev);
                });
            }
        };

        vulnsWebFact.remove = function(ws, vuln) {
            var url = BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev;
            $http.delete(url).success(function(d, s, h, c) {});
        };

        return vulnsWebFact;
    }]);
