// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

function htmlentities(string, quote_style, charset, double_encode) {
    var hash_map = translationtable('HTML_ENTITIES', quote_style), symbol = '';
    string = string == null ? '' : string + '';

    if (!hash_map) {
        return false;
    }

    if (quote_style && quote_style === 'ENT_QUOTES') {
        hash_map["'"] = '&#039;';
    }

    if ( !! double_encode || double_encode == null) {
        for (symbol in hash_map) {
            if (hash_map.hasOwnProperty(symbol)) {
                string = string.split(symbol)
                    .join(hash_map[symbol]);
            }
        }
    } else {
        string = string.replace(/([\s\S]*?)(&(?:#\d+|#x[\da-f]+|[a-zA-Z][\da-z]*);|$)/g, function (ignore, text, entity) {
            for (symbol in hash_map) {
                if (hash_map.hasOwnProperty(symbol)) {
                    text = text.split(symbol)
                        .join(hash_map[symbol]);
                }
            }
            return text + entity;
        });
    }
    return string;
};

function translationtable(table, quote_style) {
    var entities = {},
        hash_map = {},
        decimal;
    var constMappingTable = {},
        constMappingQuoteStyle = {};
    var useTable = {},
        useQuoteStyle = {};

    // Translate arguments
    constMappingTable[0]        = 'HTML_SPECIALCHARS';
    constMappingTable[1]        = 'HTML_ENTITIES';
    constMappingQuoteStyle[0]   = 'ENT_NOQUOTES';
    constMappingQuoteStyle[2]   = 'ENT_COMPAT';
    constMappingQuoteStyle[3]   = 'ENT_QUOTES';

    useTable = !isNaN(table) ? constMappingTable[table] : table ? table.toUpperCase() : 'HTML_SPECIALCHARS';
    useQuoteStyle = !isNaN(quote_style) ? constMappingQuoteStyle[quote_style] : quote_style ? quote_style.toUpperCase() :
        'ENT_COMPAT';

    if (useTable !== 'HTML_SPECIALCHARS' && useTable !== 'HTML_ENTITIES') {
        throw new Error('Table: ' + useTable + ' not supported');
    }

    entities['38'] = '&amp;';
    if (useTable === 'HTML_ENTITIES') {
    entities['160'] = '&nbsp;';
    entities['161'] = '&iexcl;';
    entities['162'] = '&cent;';
    entities['163'] = '&pound;';
    entities['164'] = '&curren;';
    entities['165'] = '&yen;';
    entities['166'] = '&brvbar;';
    entities['167'] = '&sect;';
    entities['168'] = '&uml;';
    entities['169'] = '&copy;';
    entities['170'] = '&ordf;';
    entities['171'] = '&laquo;';
    entities['172'] = '&not;';
    entities['173'] = '&shy;';
    entities['174'] = '&reg;';
    entities['175'] = '&macr;';
    entities['176'] = '&deg;';
    entities['177'] = '&plusmn;';
    entities['178'] = '&sup2;';
    entities['179'] = '&sup3;';
    entities['180'] = '&acute;';
    entities['181'] = '&micro;';
    entities['182'] = '&para;';
    entities['183'] = '&middot;';
    entities['184'] = '&cedil;';
    entities['185'] = '&sup1;';
    entities['186'] = '&ordm;';
    entities['187'] = '&raquo;';
    entities['188'] = '&frac14;';
    entities['189'] = '&frac12;';
    entities['190'] = '&frac34;';
    entities['191'] = '&iquest;';
    entities['192'] = '&Agrave;';
    entities['193'] = '&Aacute;';
    entities['194'] = '&Acirc;';
    entities['195'] = '&Atilde;';
    entities['196'] = '&Auml;';
    entities['197'] = '&Aring;';
    entities['198'] = '&AElig;';
    entities['199'] = '&Ccedil;';
    entities['200'] = '&Egrave;';
    entities['201'] = '&Eacute;';
    entities['202'] = '&Ecirc;';
    entities['203'] = '&Euml;';
    entities['204'] = '&Igrave;';
    entities['205'] = '&Iacute;';
    entities['206'] = '&Icirc;';
    entities['207'] = '&Iuml;';
    entities['208'] = '&ETH;';
    entities['209'] = '&Ntilde;';
    entities['210'] = '&Ograve;';
    entities['211'] = '&Oacute;';
    entities['212'] = '&Ocirc;';
    entities['213'] = '&Otilde;';
    entities['214'] = '&Ouml;';
    entities['215'] = '&times;';
    entities['216'] = '&Oslash;';
    entities['217'] = '&Ugrave;';
    entities['218'] = '&Uacute;';
    entities['219'] = '&Ucirc;';
    entities['220'] = '&Uuml;';
    entities['221'] = '&Yacute;';
    entities['222'] = '&THORN;';
    entities['223'] = '&szlig;';
    entities['224'] = '&agrave;';
    entities['225'] = '&aacute;';
    entities['226'] = '&acirc;';
    entities['227'] = '&atilde;';
    entities['228'] = '&auml;';
    entities['229'] = '&aring;';
    entities['230'] = '&aelig;';
    entities['231'] = '&ccedil;';
    entities['232'] = '&egrave;';
    entities['233'] = '&eacute;';
    entities['234'] = '&ecirc;';
    entities['235'] = '&euml;';
    entities['236'] = '&igrave;';
    entities['237'] = '&iacute;';
    entities['238'] = '&icirc;';
    entities['239'] = '&iuml;';
    entities['240'] = '&eth;';
    entities['241'] = '&ntilde;';
    entities['242'] = '&ograve;';
    entities['243'] = '&oacute;';
    entities['244'] = '&ocirc;';
    entities['245'] = '&otilde;';
    entities['246'] = '&ouml;';
    entities['247'] = '&divide;';
    entities['248'] = '&oslash;';
    entities['249'] = '&ugrave;';
    entities['250'] = '&uacute;';
    entities['251'] = '&ucirc;';
    entities['252'] = '&uuml;';
    entities['253'] = '&yacute;';
    entities['254'] = '&thorn;';
    entities['255'] = '&yuml;';
    }

    if (useQuoteStyle !== 'ENT_NOQUOTES') {
        entities['34'] = '&quot;';
    }
    if (useQuoteStyle === 'ENT_QUOTES') {
        entities['39'] = '&#39;';
    }
    entities['60'] = '&lt;';
    entities['62'] = '&gt;';

    // ascii decimals to real symbols
    for (decimal in entities) {
        if (entities.hasOwnProperty(decimal)) {
            hash_map[String.fromCharCode(decimal)] = entities[decimal];
        }
    }

    return hash_map;
}

function load_all_hosts(design) {
		design = "hosts";
		var iurl	= "/" + workspace + "/_design/" + design + "/_view/byinterfacecount?group=true";
		var hurl	= "/" + workspace + "/_design/" + design + "/_view/hosts";
		var surl	= "/" + workspace + "/_design/" + design + "/_view/byservicecount?group=true";
		var hosts	= new Object();
		var interfaces	= new Object();
		var services	= new Object();
		
		hosts		= get_obj(hurl);
		interfaces	= get_obj(iurl, interfaces);
		services	= get_obj(surl, services);
		var table = "<header><h2>Hosts report</h2></header>";
		table += "<table id=\"hosts-"+workspace+"\" class=\"tablesorter table table-striped\"><thead><tr>"+
				"<th>Host</th>"+
				"<th>Services</th>"+
				"<th>OS</th>"+
				"</tr></thead><tbody>";
		$.each(hosts, function(k, v){
            var hname = htmlentities(v.name);
			if(!services.hasOwnProperty(k)) {
				services[k] = 0;
			} else {
				hname = "<a href=\"host-"+k+"\" class=\"host\">"+hname+"</a>";
			}
			if(!interfaces.hasOwnProperty(k)) interfaces[k] = 0;
			var icon = "";
			if(v.os.toLowerCase().indexOf("windows") > -1) icon = "windows";
			if(v.os.toLowerCase().indexOf("osx") > -1) icon = "osx";
			if(v.os.toLowerCase().indexOf("linux") > -1
				|| v.os.toLowerCase().indexOf("unix") > -1) icon = "linux";
			var os = "";
			if(icon === "") {
				os = "<span class=\"fa fa-laptop faraday-qtips\" title="+v.os+"></span>";
			} else {
				os = "<img src=\"../././reports/images/"+icon+".png\" class=\"faraday-qtips\" title=\""+v.os+"\"/>";
			}
			table += "<tr id=\"host-"+k+"\">"+
				"<td>"+hname+"</td>"+
				"<td>"+services[k]+"</td>"+
				"<td>"+os+"</td></tr>";
		});
		table += "</tbody></table>";
		return table;
	}

	function load_hosts_by_service(name,bolean) {
        name = htmlentities(name);
		design = "hosts";
		var services 	= get_obj_filter(workspace, "services", "byname", name);
		var hids 	= [];
		$.each(services, function(k, v) {
			v = v['value'];
			if($.inArray(v['hid'], hids) < 0) {
				hids.push(v['hid']);
			}
		});
		var hosts 	= get_obj_filter(workspace, "hosts", "hosts", hids);
		var iurl	= "/" + workspace + "/_design/" + design + "/_view/byinterfacecount?group=true";
		var interfaces	= new Object();
		var surl	= "/" + workspace + "/_design/" + design + "/_view/byservicecount?group=true";
		var scount	= new Object();

		interfaces	= get_obj(iurl, interfaces);
		scount		= get_obj(surl, services);
		if(!bolean){
			var table = "<header><h2>Hosts with Service "+name+" ("+hids.length+" total)</h2></header><div id='text'></div>"+
					"<table id=\"hosts-"+workspace+"\" class=\"tablesorter table table-striped\"><thead><tr>"+
					"<th>Host</th>"+
					"<th>Services</th>"+
					"<th>OS</th>"+
					"</tr></thead><tbody>";
			$.each(hosts, function(k, v){
				var id = v['id'];
				v = v['value'];
				var icon = "";
                var tmp = "";
                var cleanOs = htmlentities(v.os);
				if(cleanOs.toLowerCase().indexOf("windows") > -1) icon = "windows";
				if(cleanOs.toLowerCase().indexOf("osx") > -1) icon = "osx";
				if(cleanOs.toLowerCase().indexOf("linux") > -1
					|| cleanOs.toLowerCase().indexOf("unix") > -1) icon = "linux";
				var os = "";
				if(icon === "") {
					os = "<span class=\"fa fa-laptop faraday-qtips\" title="+cleanOs+"></span>";
				} else {
					os = "<img src=\"../././reports/images/"+icon+".png\" class=\"faraday-qtips\" title=\""+cleanOs+"\"/>";
				}
                tmp = htmlentities(v['name']);
				if($.inArray(id, hids) > -1) {
					table += "<tr id=\"host-"+id+"\">"+
						"<td><a href=\"host-"+id+"\" class=\"host\">"+tmp+"</a></td>"+
						"<td>"+scount[id]+"</td>"+
						"<td>"+os+"</td></tr>";
				}
			});
			table += "</tbody></table>";
		}else{
			var table = "<table><tbody>"; 
			$.each(hosts, function(k, v){
			var id = v['id'];
			v = v['value'];
            var tmp = htmlentities(v['name']);
			if($.inArray(id, hids) > -1) {
				table += "<tr id=\"host-"+id+"\">"+
					"<td><p>"+tmp+"</p></td></tr>";
			}
			});
			table += "</tbody></table>";
		}
		return table;
	}

	function load_services(hid, hname) {
        hname = htmlentities(hname);
		design = "hosts";
		// el param design ya no es el recibido por GET, puesto que ahora estamos en services
		var services = get_obj_filter(workspace, "services", "byhost", hid);
		var table = "<header><h2>Services for Host "+hname+" ("+services.length+" total)</h2></header><div id='text'></div>"+
			"<table id=\"services-"+workspace+"\" class=\"tablesorter table table-striped\"><thead><tr>"+
			"<th>Name</th>"+
			"<th>Description</th>"+
			"<th>Ports</th>"+
			"<th>Protocol</th>"+
			"<th>Status</th></tr></thead><tbody>";
		$.each(services, function(k, v){
				var sid = v['id'];
				v = v['value'];
				var desc = (v['description'] === "") ? "n/a" : htmlentities(v['description']);
				var ports = "";
                var sname = "";
				if(v['ports'].length === 0) {
					ports = "no ports available";
				} else {
					for(i=0; i < v['ports'].length; i++){
						ports += htmlentities(v['ports'][i]);
						if(v['ports'].length != 1 && i != (v['ports'].length-1)) {
							ports += ", ";
						}
					}
				}
                sname = htmlentities(v['name']);
                protocol = htmlentities(v['protocol']);
                status = htmlentities(v['status']);
				table += "<tr id=\"service-"+sid+"\">"+
					"<td><a href=\"service-"+sid+"\" class=\"service\">"+sname+"</a></td>"+
					"<td>"+desc+"</td>"+
					"<td>"+ports+"</td>"+
					"<td>"+protocol+"</td>"+
					"<td>"+status+"</td></tr>";
		});
		table += "</tbody></table>";
		return table;
	}

	function get_obj_filter(ws, design, view, key) {
		var db = new CouchDB(ws);
		var sview = design + "/" + view;
		if(typeof key === 'undefined') {
			var matches = db.view(sview);
		} else if($.isArray(key)) {
			var matches = db.view(sview, {keys: JSON.stringify(key)});
		} else {
			var matches = db.view(sview, {key: key});
		}
		return matches.rows;
	}

	function get_obj(ourl) {
		var ls = {};
		$.ajax({
			dataType: "json",
			url: ourl,
			async: false,
			success: function(data) {
				$.each(data.rows, function(n, obj){
					ls[obj.key] = obj.value;
				});	
			}
		});
		return ls;
	}

	function back_to_services(hid,hname){
		$(document).on('click', 'a#back_to_services', function(e) {
			var div = load_services(hid, hname);
			$("#hosts").html(div);
			$("#text").html("<a href=\"load_all_hosts\">View all hosts</a> - <a id='back_to_host'>Back</a>");
			sorter(2);
			$("#compound .tablesorter tbody td, #compound .tablesorter thead th").css("width","20%");
		});
	}
	//sortea la columna que vos le pasas, columna = numero 
	function sorter(columna){
		$(".tablesorter").tablesorter({
          	 sortList: [[columna,0]] 
        });
	}

$( document ).ready(function() {
	$(document).on('click', 'a.host', function(e) {
            // no queremos que cargue nada
            e.preventDefault();
            // el ID del host que quiero traer es el ID del link clickeado menos el "host-" del ppio
            var hid = $(this).attr("href").split('-')[1];
            // el nombre del host que quiero traer es el valor del link
            var hname = $(this).text();
            var div = load_services(hid, hname);
            back_to_services(hid,hname);
            $("#hosts").html(div);
            // sacamos la tabla de hosts y agregamos un link de navegacion para volverla a cargar
            $("#text").html("<a href=\"load_all_hosts\">View all hosts</a> - <a id='back_to_host'>Back</a>");
            sorter(2);
            $("#compound .tablesorter thead th, #compound .tablesorter tbody td").css("width","20%");
});
        // cuando se clickea un servicio carga todos los hosts que tienen ese servicio
        $(document).on('click', 'a.service', function(e) {
            e.preventDefault();
            var sname = $(this).text();
            var div = load_hosts_by_service(sname);
            $("#hosts").html(div);
            // sacamos la tabla de hosts y agregamos un link de navegacion para volverla a cargar
            $("#text").html("<a href=\"load_all_hosts\">View all hosts</a> - <a id='back_to_services'>Back</a>");
            sorter(0);
        });

        // comportamiento para "View all hosts"
        $(document).on('click', 'a[href="load_all_hosts"]', function(e) {
            e.preventDefault();
            var div = load_all_hosts();
            $("#hosts").html(div);
            sorter(0);
        });
        $(document).on('click', 'a#back_to_host', function(e) {
		    e.preventDefault();
            var div = load_all_hosts();
            $("#hosts").html(div);
            sorter(0);
        });
});
