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
		var table = "<header><h2>Hosts report</h2></header><div class='main'>";
		table += "<table id=\"hosts-"+workspace+"\" class=\"tablesorter\"><thead><tr>"+
				"<th>Host</th>"+
				"<th>Services</th>"+
				"<th>OS</th>"+
				"</tr></thead><tbody>";
		$.each(hosts, function(k, v){
			var hname = "";
			if(!services.hasOwnProperty(k)) {
				services[k] = 0;
				hname = v.name;
			} else {
				hname = "<a href=\"host-"+k+"\" class=\"host\">"+v.name+"</a>";
			}
			if(!interfaces.hasOwnProperty(k)) interfaces[k] = 0;
			var icon = "";
			if(v.os.toLowerCase().indexOf("windows") > -1) icon = "windows";
			if(v.os.toLowerCase().indexOf("osx") > -1) icon = "osx";
			if(v.os.toLowerCase().indexOf("linux") > -1
				|| v.os.toLowerCase().indexOf("unix") > -1) icon = "linux";
			var os = "";
			if(icon === "") {
				os = "<span title=\""+v.os+"\">undefined</span>";
			} else {
				os = "<img src=\"../././reports/images/"+icon+".png\" title=\""+v.os+"\"/>";
			}
			table += "<tr id=\"host-"+k+"\">"+
				"<td>"+hname+"</td>"+
				"<td>"+services[k]+"</td>"+
				"<td>"+os+"</td></tr>";
		});
		table += "</tbody></table></div>";
		return table;
	}

	function load_hosts_by_service(name,bolean) {
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
			var table = "<header><h2>Hosts with Service "+name+" ("+hids.length+" total)</h2></header><header class='texto'><p id='text'></p></header><div class='main' style='height:338px'>"+
					"<table id=\"hosts-"+workspace+"\" class=\"tablesorter\"><thead><tr>"+
					"<th>Host</th>"+
					"<th>Services</th>"+
					"<th>OS</th>"+
					"</tr></thead><tbody>";
			$.each(hosts, function(k, v){
				var id = v['id'];
				v = v['value'];
				var icon = "";
				if(v.os.toLowerCase().indexOf("windows") > -1) icon = "windows";
				if(v.os.toLowerCase().indexOf("osx") > -1) icon = "osx";
				if(v.os.toLowerCase().indexOf("linux") > -1
					|| v.os.toLowerCase().indexOf("unix") > -1) icon = "linux";
				var os = "";
				if(icon === "") {
					os = "<span title=\""+v.os+"\">undefined</span>";
				} else {
					os = "<img src=\"../././reports/images/"+icon+".png\" title=\""+v.os+"\"/>";
				}
				if($.inArray(id, hids) > -1) {
					table += "<tr id=\"host-"+id+"\">"+
						"<td><a href=\"host-"+id+"\" class=\"host\">"+v['name']+"</a></td>"+
						"<td>"+scount[id]+"</td>"+
						"<td>"+os+"</td></tr>";
				}
			});
			table += "</tbody></table></div>";
		}else{
			var table = "<table><tbody>"; 
			$.each(hosts, function(k, v){
			var id = v['id'];
			v = v['value'];
			if($.inArray(id, hids) > -1) {
				table += "<tr id=\"host-"+id+"\">"+
					"<td><p>"+v['name']+"</p></td></tr>";
			}
			});
			table += "</tbody></table>";
		}
		return table;
	}

	function load_services(hid, hname) {
		design = "hosts";
		// el param design ya no es el recibido por GET, puesto que ahora estamos en services
		var services = get_obj_filter(workspace, "services", "byhost", hid);
		var table = "<header><h2>Services for Host "+hname+" ("+services.length+" total)</h2></header><header class='texto'><p id='text'></p></header><div class='main' style='height:338px'>"+
			"<table id=\"services-"+workspace+"\" class=\"tablesorter\"><thead><tr>"+
			"<th>Name</th>"+
			"<th>Description</th>"+
			"<th>Ports</th>"+
			"<th>Protocol</th>"+
			"<th>Status</th></tr></thead><tbody>";
		$.each(services, function(k, v){
				var sid = v['id'];
				v = v['value'];
				var desc = (v['description'] === "") ? "n/a" : v['description'];
				var ports = "";
				if(v['ports'].length === 0) {
					ports = "no ports available";
				} else {
					for(i=0; i < v['ports'].length; i++){
						ports += v['ports'][i];
						if(v['ports'].length != 1 && i != (v['ports'].length-1)) {
							ports += ", ";
						}
					}
				}
				table += "<tr id=\"service-"+sid+"\">"+
					"<td><a href=\"service-"+sid+"\" class=\"service\">"+v['name']+"</a></td>"+
					"<td>"+desc+"</td>"+
					"<td>"+ports+"</td>"+
					"<td>"+v['protocol']+"</td>"+
					"<td>"+v['status']+"</td></tr>";
		});
		table += "</tbody></table></div>";
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
		});
	}
	//sortea la columna que vos le pasas, columna = numero 
	function sorter(columna){
		$(".tablesorter").tablesorter({
          	 sortList: [[columna,0]] 
        });
	}

$( document ).ready(function() {
    $('#cont').on('mouseenter', 'img[title]', function (event) {
        $(this).qtip({
            overwrite: false, // Don't overwrite tooltips already bound
            show: {
                event: event.type, // Use the same event type as above
                ready: true // Show immediately - important!
            },
            hide: {
                fixed: true,
                delay: 300
            },
            content:{
                text: function(event, api) {
                    var name = $(this).attr("title");
                    var hosts = "<div id='contenido'>" +name+ "</div>";
                    return hosts;
                }
            },
            position:{
                my: 'top center',
                at: 'bottom center',
                adjust: {
                    method: 'shift'
                }
            }
        });
    });
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
