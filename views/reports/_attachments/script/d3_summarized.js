function treemap(workspace, design, view){
	        var margin = {top: 28, right: 10, bottom: 10, left: 10},
            width = 250 - margin.left - margin.right,
            height = 200 - margin.top - margin.bottom;

        var color = d3.scale.category20c();

        var treemap = d3.layout.treemap()
            .size([width, height])
            .sticky(true)
            .value(function(d) {return d.value});

        var div = d3.select("#treemap").append("div")
            .style("position", "relative")
            .style("width", (width + margin.left + margin.right) + "px")
            .style("height", (height + margin.top + margin.bottom) + "px")
            .style("left", margin.left + "px")
            .style("top", margin.top + "px");

      
        json_url = "/" + workspace + "/_design/" + design + "/_view/" + view + "?group=true";
        d3.json(json_url, function(error, root) {
          var sort_jotason = sorter_jotason(root);
          var jotason = {};
          jotason["children"] = sort_jotason;
          var node = div.datum(jotason).selectAll(".node")
              .data(treemap.nodes)
            .enter().append("div")
              .attr("class", "node")
              .call(position)
              .style("background", function(d) {return color(Math.floor(Math.random()*68)); })
              .text(function(d) {return d.children ? null : d.key; });
              
          d3.select("#size").on("click", function() {
             div.selectAll("div")
                 .data(treemap.value(function(d) { return d.value - 10; }))
               .transition()
                 .duration(1500)
                 .call(position);
         
             d3.select("#size").classed("active", true);
             d3.select("#count").classed("active", false);
           });

         d3.select("#count").on("click", function() {
           div.selectAll("div")
               .data(treemap.value(function(d) {return d.value + 10; }))
             .transition()
               .duration(1500)
               .call(position);
       
           d3.select("#size").classed("active", false);
           d3.select("#count").classed("active", true);
         });
        });

        function position() {
          this.style("left", function(d) { return d.x + "px"; })
              .style("top", function(d) { return d.y + "px"; })
              .style("width", function(d) { return Math.max(0, d.dx - 1) + "px"; })
              .style("height", function(d) { return Math.max(0, d.dy - 1) + "px"; });
        }

        function sorter_jotason(root){
        	var arr = [];
	        var row = root.rows;
	        for (i = 0; i < row.length; i++) {
	            arr.push(row[i].value,row[i].key);
	        }
	        obj = [];
	        var obj = row.sort(function(a,b){ 
	            if (a[0] === b[0]) {
	                return 0;
	            }
	            else {
	                return (a[0] > b[0]) ? -1 : 1;
	            }
	            return obj;
	        });
	        var objeto = [];
	        for(i = 0; i < 5; i++){
	        	objeto.push(obj[i]);
	        }
	        return objeto;
        }
}

function bar(workspace, design, view){
	// Mapping of step names to colors.
	var colors = {
	  "low": "#A1CE31",
	  "med": "#DFBF35",
	  "critical": "#8B00FF",
	  "high": "#B80000",
	  "info": "#ddd"
	};

	var margin = {top: 20, right: 20, bottom: 30, left: 40},
	    width = 250 - margin.left - margin.right,
	    height = 200 - margin.top - margin.bottom;

	var x = d3.scale.ordinal()
	    .rangeRoundBands([0, width], .1);

	var y = d3.scale.linear()
	    .range([height, 0]);

	var xAxis = d3.svg.axis()
	    .scale(x)
	    .orient("bottom");

	var yAxis = d3.svg.axis()
	    .scale(y)
	    .orient("left")
	    .ticks(5);

	var svg = d3.select("#bar").append("svg")
	    .attr("width", width + margin.left + margin.right)
	    .attr("height", height + margin.top + margin.bottom)
	  .append("g")
	    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

	json_url = "/" + workspace + "/_design/" + design + "/_view/" + view + "?group=true";
	d3.json(json_url, function(error, root) {
	    var jotason = [];
	    jotason["children"] = root["rows"];
	  var data = get_low(jotason);

	  x.domain(data.map(function(d) { return d.key; }));
	  y.domain([0, d3.max(data, function(d) { return d.value; })]);

	  svg.append("g")
	      .attr("class", "x axis")
	      .attr("transform", "translate(0," + height + ")")
	      .call(xAxis);

	  svg.append("g")
	      .attr("class", "y axis")
	      .call(yAxis)
	    .append("text")
	      .attr("transform", "rotate(-90)")
	      .attr("y", 6)
	      .attr("dy", ".71em")
	      .style("text-anchor", "end")
	      .text("Value");

	  svg.selectAll(".bar")
	      .data(data)
	    .enter().append("rect")
	      .attr("class", "bar")
	      .attr("x", function(d) { return x(d.key); })
	      .attr("width", x.rangeBand())
	      .attr("y", function(d) { return y(d.value); })
	      .style("fill", function(d) {return colors[d.key]; })
	      .attr("height", function(d) { return height - y(d.value); });
	});

	function type(d) {
	  d.value = +d.value;
	  return d;
	}
	function get_low(jotason){
	  var children = jotason["children"];
	  for (i = 0; i < 5; i++) {
	      jotason[i] = {};
	      jotason[i].value = 0;
	  }
	  jotason[0].key = "info";
	  jotason[1].key = "low";
	  jotason[2].key = "med";
	  jotason[3].key = "high";
	  jotason[4].key = "critical";

	  for(i = 0; i < children.length; i++){
	    if(children[i].key == 1 || children[i].key == "Information" || children[i].key == "info"){
	      jotason[0].value += children[i].value;
	    }
	    if(children[i].key == 2 || children[i].key == "Low"){
	      jotason[1].value += children[i].value;
	    }
	    if(children[i].key == 3 || children[i].key == "Medium"){
	      jotason[2].value += children[i].value;
	    }
	    if(children[i].key == 4 || children[i].key == "High"){
	      jotason[3].value += children[i].value;
	    }
	    if(children[i].key == 5 || children[i].key == "Critical"){
	      jotason[4].value += children[i].value;
	    }
	  }
	  delete jotason["children"]
	  return jotason;
	}
}

function cake(workspace, design, view){
	// Dimensions of sunburst.
	var width = 250;
	var height = 200;
	var radius = Math.min(width, height) / 2;

	// Breadcrumb dimensions: width, height, spacing, width of tip/tail.
	var b = {
	  w: 75, h: 30, s: 3, t: 10
	};

	// Mapping of step names to colors.
	var colors = {
	  "low": "#A1CE31",
	  "med": "#DFBF35",
	  "critical": "#8B00FF",
	  "high": "#B80000",
	  "info": "#ddd"
	};

	// Total size of all segments; we set this later, after loading the data.
	var totalSize = 0; 

	var vis = d3.select("#chart").append("svg:svg")
	    .attr("width", width)
	    .attr("height", height)
	    .append("svg:g")
	    .attr("id", "container")
	    .attr("transform", "translate(" + width / 2 + "," + height / 2 + ")");

	var partition = d3.layout.partition()
	    .size([2 * Math.PI , radius * radius])
	    .value(function(d) { return d.value; });

	var arc = d3.svg.arc()
	    .startAngle(function(d) { return d.x; })
	    .endAngle(function(d) { return d.x + d.dx; })
	    .innerRadius(function(d) { return Math.sqrt(d.y); })
	    .outerRadius(function(d) { return Math.sqrt(radius); });

	    json_url = "/" + workspace + "/_design/" + design + "/_view/" + view + "?group=true";
	    d3.json(json_url, function(error, root) {
	    var jotason = {};
	    jotason["children"] = root["rows"];
	    var json_finish = get_low(jotason);
	    createVisualization(json_finish);
	  });

	// Main function to draw and set up the visualization, once we have the data.
	function createVisualization(json) {
	  // Basic setup of page elements.
	  initializeBreadcrumbTrail();
	  drawLegend();
	  d3.select("#togglelegend").on("click", toggleLegend);

	  // Bounding circle underneath the sunburst, to make it easier to detect
	  // when the mouse leaves the parent g.
	  vis.append("svg:circle")
	      .attr("r", radius)
	      .style("opacity", 0);

	  // For efficiency, filter nodes to keep only those large enough to see.
	  var nodes = partition.nodes(json)
	      .filter(function(d) {
	      return (d.dx > 0.005); // 0.005 radians = 0.29 degrees
	      });

	  var path = vis.data([json]).selectAll("path")
	      .data(nodes)
	      .enter().append("svg:path")
	      .attr("display", function(d) { return d.depth ? null : "none"; })
	      .attr("d", arc)
	      .attr("fill-rule", "evenodd")
	      .style("fill", function(d) {return colors[d.key]; })
	      .style("stroke-width", "0.5")
	      .style("opacity", 1)
	      .on("mouseover", mouseover);

	  // Add the mouseleave handler to the bounding circle.
	  d3.select("#container").on("mouseleave", mouseleave);

	  // Get total size of the tree = value of root node from partition.
	  totalSize = path.node().__data__.value;
	 };

	// Fade all but the current sequence, and show it in the breadcrumb trail.
	function mouseover(d) {

	  var percentage = (100 * d.value / totalSize).toPrecision(3);
	  var percentageString = d.key +": "+ d.value + " " + percentage + "%";
	  if (percentage < 0.1) {
	    percentageString = d.value;
	  }

	  var sequenceArray = getAncestors(d);

	  // Fade all the segments.
	  d3.selectAll("path")
	      .style("opacity", 0.7);

	  // Then highlight only those that are an ancestor of the current segment.
	  vis.selectAll("path")
	      .filter(function(node) {
	                return (sequenceArray.indexOf(node) >= 0);
	              })
	      .style("opacity", 1);
	}

	// Restore everything to full opacity when moving off the visualization.
	function mouseleave(d) {

	  // Hide the breadcrumb trail
	  d3.select("#trail")
	      .style("visibility", "hidden");

	  // Deactivate all segments during transition.
	  d3.selectAll("path").on("mouseover", null);

	  // Transition each segment to full opacity and then reactivate it.
	  d3.selectAll("path")
	      .transition()
	      .duration(1000)
	      .style("opacity", 1);

	  d3.select("#explanation")
	      .style("visibility", "hidden");
	}

	// Given a node in a partition layout, return an array of all of its ancestor
	// nodes, highest first, but excluding the root.
	function getAncestors(node) {
	  var path = [];
	  var current = node;
	  while (current.parent) {
	    path.unshift(current);
	    current = current.parent;
	  }
	  return path;
	}

	function initializeBreadcrumbTrail() {
	  // Add the svg area.
	  var trail = d3.select("#sequence").append("svg:svg")
	      .attr("width", width)
	      .attr("height", 50)
	      .attr("id", "trail");
	  // Add the label at the end, for the percentage.
	  trail.append("svg:text")
	    .attr("id", "endlabel")
	    .style("fill", "#000");
	}

	// Generate a string that describes the points of a breadcrumb polygon.
	function breadcrumbPoints(d, i) {
	  var points = [];
	  points.push("0,0");
	  points.push(b.w + ",0");
	  points.push(b.w + b.t + "," + (b.h / 2));
	  points.push(b.w + "," + b.h);
	  points.push("0," + b.h);
	  if (i > 0) { // Leftmost breadcrumb; don't include 6th vertex.
	    points.push(b.t + "," + (b.h / 2));
	  }
	  return points.join(" ");
	}

	// Update the breadcrumb trail to show the current sequence and percentage.
	function updateBreadcrumbs(nodeArray, percentageString) {

	  // Data join; key function combines name and depth (= position in sequence).
	  var g = d3.select("#trail")
	      .selectAll("g")
	      .data(nodeArray, function(d) { return d.key + d.depth; });

	  // Add breadcrumb and label for entering nodes.
	  var entering = g.enter().append("svg:g");

	  entering.append("svg:polygon")
	      .attr("points", breadcrumbPoints)
	      .style("fill", function(d) {return colors[d.key]; });

	  entering.append("svg:text")
	      .attr("x", (b.w + b.t) / 2)
	      .attr("y", b.h / 2)
	      .attr("dy", "0.35em")
	      .attr("text-anchor", "middle")
	      .text(function(d) { return d.key; });

	  // Set position for entering and updating nodes.
	  g.attr("transform", function(d, i) {
	    return "translate(" + i * (b.w + b.s) + ", 0)";
	  });

	  // Remove exiting nodes.
	  g.exit().remove();

	  // Now move and update the percentage at the end.
	  d3.select("#trail").select("#endlabel")
	      .attr("x", (nodeArray.length + 0.5) * (b.w + b.s + 10))
	      .attr("y", b.h / 2)
	      .attr("dy", "0.35em")
	      .attr("text-anchor", "middle")
	      .text(percentageString);

	  // Make the breadcrumb trail visible, if it's hidden.
	  d3.select("#trail")
	      .style("visibility", "");

	}

	function drawLegend() {

	  // Dimensions of legend item: width, height, spacing, radius of rounded rect.
	  var li = {
	    w: 75, h: 30, s: 3, r: 3
	  };

	  var legend = d3.select("#legend").append("svg:svg")
	      .attr("width", li.w)
	      .attr("height", d3.keys(colors).length * (li.h + li.s));

	  var g = legend.selectAll("g")
	      .data(d3.entries(colors))
	      .enter().append("svg:g")
	      .attr("transform", function(d, i) {
	              return "translate(0," + i * (li.h + li.s) + ")";
	           });

	  g.append("svg:rect")
	      .attr("rx", li.r)
	      .attr("ry", li.r)
	      .attr("width", li.w)
	      .attr("height", li.h)
	      .style("fill", function(d) { return d.value; });

	  g.append("svg:text")
	      .attr("x", li.w / 2)
	      .attr("y", li.h / 2)
	      .attr("dy", "0.35em")
	      .attr("text-anchor", "middle")
	      .text(function(d) { return d.key; });
	}

	function toggleLegend() {
	  var legend = d3.select("#legend");
	  if (legend.style("visibility") == "hidden") {
	    legend.style("visibility", "");
	  } else {
	    legend.style("visibility", "hidden");
	  }
	}
	function get_low(jotason){
	  var children = jotason["children"];
	  for (i = 0; i < 5; i++) {
	      jotason[i] = {};
	      jotason[i].value = 0;
	  }
	  jotason[0].key = "info";
	  jotason[1].key = "low";
	  jotason[2].key = "med";
	  jotason[3].key = "high";
	  jotason[4].key = "critical";

	  for(i = 0; i < children.length; i++){
	    if(children[i].key == 1 || children[i].key == "Information" || children[i].key == "info"){
	      jotason[0].value += children[i].value;
	    }
	    if(children[i].key == 2 || children[i].key == "Low"){
	      jotason[1].value += children[i].value;
	    }
	    if(children[i].key == 3 || children[i].key == "Medium"){
	      jotason[2].value += children[i].value;
	    }
	    if(children[i].key == 4 || children[i].key == "High"){
	      jotason[3].value += children[i].value;
	    }
	    if(children[i].key == 5 || children[i].key == "Critical"){
	      jotason[4].value += children[i].value;
	    }
	  }
	  jotason["children"] = [];
	  for (i = 0; i < 5; i++) {
	      jotason["children"].push(jotason[i]);
	  }
	  return jotason;
	}

}