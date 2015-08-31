// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
  .directive('d3Bars', ['d3Service', '$routeParams',
  function(d3Service, $routeParams) {
    return {
      restrict: 'EA',
      scope: {
        data: '='
      },
      link: function(scope, ele, attrs) {
        d3Service.d3().then(function(d3) {
 
          var margin = {
            "top": parseInt(attrs.marginTop) || 20,
            "right": parseInt(attrs.marginRight) || 20,
            "bottom": parseInt(attrs.marginBottom) || 30,
            "left": parseInt(attrs.marginLeft) || 40
          }

          var barHeight = parseInt(attrs.barHeight) || 20,
              barPadding = parseInt(attrs.barPadding) || 5,
              width = parseInt(attrs.svgWitdh) || 160,
              height = parseInt(attrs.svgHeight) || 149;
 
          scope.$watch('data', function(newData) {
            scope.render(newData);
          }, true);
 
          scope.render = function(data) {

            // remove existing treemap container, if any
            d3.select("#bar_container").remove();
 
            if (!data || data.length == 0) return;

            var svg = d3.select(ele[0])
              .append("div")
              .attr("class", "box")
              .attr("id", "bar_container")
              .append("svg")
                .attr("width", width)
                .attr("height", height)
              .append("g")
                .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

            var color = d3.scale.category20b();
            var x = d3.scale.ordinal()
                .rangeRoundBands([0, width - margin.left - margin.right], .1);
            
            var y = d3.scale.linear()
                .range([height - margin.top - margin.bottom, 0]);

            var xAxis = d3.svg.axis()
                .scale(x)
                .orient("bottom");
            var yAxis = d3.svg.axis()
                .scale(y)
                .orient("left")
                .ticks(5);

            x.domain(data.map(function(d) { return d.key; }));
            y.domain([0, d3.max(data, function(d) { return d.value; })]);

            svg.selectAll('.bar')
              .data(data)
              .enter()
                .append('rect')
                .attr("class", function(d) { return "id-" + d.key + " bar"; })
                .attr("x", function(d) { return x(d.key); })
                .attr("y", function(d) { return y(d.value - 0.5); })
                .style("fill", function(d) { return color(Math.random()*55); })
                .attr("height", function(d) { return height - margin.top - margin.bottom - y(d.value); })
                .attr("width", 30)
                .style('opacity', 0)
                .on('mouseover', function(d) {
                    workspace = $routeParams.wsId;
                    var hurl    = "/" + workspace + "/_design/hosts/_view/hosts";
                    hosts    = get_obj(hurl);
                    var name = hosts[d.key].name;
                    document.getElementById("barText").innerHTML =  "<div style='background-color:" + d.color + "'><b>" + name + '</b></div>' + d.value;
                })
                .on('mouseenter', function(d) {
                    var line = d3.select('.id-'+d.key)
                        .style("opacity", 1);
                })
                .on('mouseleave', function(d) {
                    document.getElementById("barText").innerHTML = "";
                    var line = d3.select('.id-'+d.key)
                        .style("opacity", 0.8);
                })
                .transition()
                    .duration(1250)
                    .style('opacity', 0.8);

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
          };
        });
      }}
  }]);
