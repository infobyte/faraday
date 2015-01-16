angular.module('faradayApp')
    .factory('vulnsFact', ['BASEURL', '$http', '$q', function(BASEURL, $http, $q) {
        var vulnsFact = {};

        vulnsFact.get = function(ws) {
            var vulns = [];
            vulns_url = BASEURL + ws +"/_design/vulns/_view/vulns";
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
                        "web":          false
                    };
                    vulns.push(v);
                });
            });
            return vulns;
        }

        vulnsFact.put = function(ws, vuln, callback) {
            var url = BASEURL + ws + "/" + vuln.id, 
            v = {
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
                "type":         vuln.type
            };
            if(typeof(vuln.evidence) != undefined && vuln.evidence != undefined) {
                vulnsFact.loadAttachments(vuln.evidence).then(function(result) {
                    var attachments = {};
                    result.forEach(function(attachment) {
                        attachments[attachment.filename] = attachment.value;
                    });
                    
                    v._attachments = attachments;
                    $http.put(url, v).success(function(d, s, h, c) {
                        callback(d.rev);
                    });
                });
            }
        };

        vulnsFact.loadAttachments = function(files) {
            var deferred = $q.defer(),
            promises = [];
            files.forEach(function(file) {
                promises.push(vulnsFact.loadAttachment(file));
            });
            $q.all(promises).then(function(attachments) {
                deferred.resolve(attachments);
            });

            return deferred.promise;
        };

        vulnsFact.loadAttachment = function(file) {
            var deferred = $q.defer(),
            filename = encodeURIComponent(file.name),
            filetype = file.type.replace("/", "\/"),
            fileReader = new FileReader();
            fileReader.readAsDataURL(file);
            fileReader.onloadend = function (readerEvent) {
                result = readerEvent.target.result;
                result = result.slice(result.indexOf(',')+1);
                deferred.resolve({"filename": filename, "value": {"content_type": filetype, "data": result}});
            };

            return deferred.promise;
        };

        vulnsFact.remove = function(ws, vuln) {
            var url = BASEURL + ws + "/" + vuln.id + "?rev=" + vuln.rev;
            $http.delete(url).success(function(d, s, h, c) {});
        };

        return vulnsFact;
    }]);
