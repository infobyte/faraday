// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .factory('csvService', function() {
        var csvService = {};

        csvService.generator = function(properties, values, ws) {
            var values = angular.copy(values);
            var obj_content = "",
            aProperties = [];
            if (ws === null) {
                var title = 'Vulnerability Model CSV'
            } else {
                var title = "SR-" + ws
            }


            for(key in properties) {
                if(properties.hasOwnProperty(key)) {
                    if(properties[key] === true) {
                        aProperties.push(key);
                    }
                }
            }
            values.forEach(function(v) {
                aProperties.forEach(function(prop) {
                    object = {};
                    if(typeof(v[prop]) === "object") v[prop] = parseObject(v[prop]);
                    if(typeof(v[prop]) != "undefined" && v[prop] != null) {
                        object[prop] = cleanCSV(v[prop]);
                    } else {
                        object[prop] = "";
                    }
                    if(prop === "date") object[prop] = parseDate(v["metadata"]["create_time"] * 1000);
                    if(prop === "creator") object[prop] = excelEscape(v["metadata"]["creator"]);
                    if(prop === "web") {
                        if(v.type === "Vulnerability") {
                            object[prop] = false;
                        } else {
                            object[prop] = true;
                        }
                    }
                    obj_content += "\"" + object[prop] + "\",";
                });
                obj_content = obj_content.substring(0, obj_content.length - 1);
                obj_content += "\n";
            });
            var content = JSON.stringify(aProperties).replace(/\[|\]/g,"") + "\n" + obj_content;
            var csvObj = {
                "content":  content,
                "extension": "csv",
                "title":    title,
                "type": "text/csv"
            };

            return csvObj;
        };

        cleanCSV = function(field) {
            return excelEscape(field.replace(/\"/g, "\"\""));
        };

        parseObject = function(object) {
            if (object === null || object === undefined) return "";
            var parsedData = "";
            if(object.length === undefined) {
                for(key in object){
                    if(object.hasOwnProperty(key)) {
                        parsedData += key + ":" + object[key] + "\n";
                    }
                }
            } else {
                object.forEach(function(obj, k) {
                    parsedData += obj + "\n";
                });
            }
            parsedData = parsedData.substring(0, parsedData.length - 1);
            return excelEscape(parsedData);
        };

        parseDate = function(date) {
            var d = new Date(date);
            return excelEscape(d.getMonth()+1 +"/" + d.getDate() + "/" + d.getFullYear());
        };

        excelEscape = function(data){
            // Patch possible formula injection attacks
            // See https://www.contextis.com/resources/blog/comma-separated-vulnerabilities/ for more info.
            if(data.startsWith('=') || data.startsWith('+')
                                    || data.startsWith('-')
                                    || data.startsWith('@')){
                return "'" + data
            }else{
                return data
            }
        }

        return csvService;
    });
