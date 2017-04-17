// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
  .directive('d3Cake', ['d3Service', 
  function(d3Service) {
    return {
      restrict: 'EA',
      scope: {
        data: '='
      },
      link: function(scope, ele, attrs) {
        d3Service.d3().then(function(d3) {
 
          var margin = {
            "top": parseInt(attrs.marginTop) || 28,
            "right": parseInt(attrs.marginRight) || 10,
            "bottom": parseInt(attrs.marginBottom) || 10,
            "left": parseInt(attrs.marginLeft) || 10
          }

          var width = parseInt(attrs.cakeWitdh) || 160,
            height = parseInt(attrs.cakeHeight) || 149,
            radius = parseInt(attrs.cakeRadius) || Math.min(width, height) / 2;

          // Breadcrumb dimensions: width, height, spacing, width of tip/tail.
          var b = {
            w: 75, h: 30, s: 3, t: 10
          };

          scope.$watch('data', function(newData) {
            scope.render(newData);
          }, true);
 
          scope.render = function(data) {

            // remove existing treemap container, if any
            d3.select("#chart").remove();
            d3.select("#sequence").remove();
 
            if (!data || data.length == 0) return;

            // we need to make a copy of the data, because the treemap is going to change it
            // and we have a watcher for that data to re-render the treemap, so we can enter
            // in a recursion loop
            var data_cp = {};
            angular.copy(data, data_cp);

            var totalSize = 0;

            var vis = d3.select(ele[0])
              .append("div")
              .attr("class", "box")
              .attr("id", "chart")
              .append("svg:svg")
                .attr("class", "box")
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

            // Bounding circle underneath the sunburst, to make it easier to detect
            // when the mouse leaves the parent g.
            vis.append("svg:circle")
                .attr("r", radius)
                .style("opacity", 0);

            // For efficiency, filter nodes to keep only those large enough to see.
            var nodes = partition.nodes(data_cp)
                .filter(function(d) {
                return (d.dx > 0.005); // 0.005 radians = 0.29 degrees
                });

            var path = vis.data([data_cp]).selectAll("path")
                .data(nodes)
                .enter().append("svg:path")
                .attr("display", function(d) { return d.depth ? null : "none"; })
                .attr("d", arc)
                .attr("fill-rule", "evenodd")
                .attr("class", function(d) {
                    var key = "";
                    if(d.key) {
                        key = "cake-" + d.key;
                    } 
                    return key;
                })
                .style("fill", function(d) {return d.color; })
                .style("stroke-width", "0.5")
                .style("opacity", 0)
                .on('mouseover', function(d) {
                    document.getElementById("cakeText").innerHTML = "<div style='background-color:" + d.color + "'><b>" + d.key + '</b></div>' + d.value;
                })
                .on('mouseenter', function(d) {
                    var slice = d3.select('.cake-'+d.key)
                        .style("opacity", 1);
                })
                .on('mouseleave', function(d) {
                    var slice = d3.select('.cake-'+d.key)
                        .style("opacity", 0.8);
                    document.getElementById("cakeText").innerHTML = "";
                })
                .transition()
                    .duration(1250)
                    .style('opacity', 0.8);

            // Get total size of the tree = value of root node from partition.
            totalSize = path.node().__data__.value;
          };
        });
      }}
  }]);
