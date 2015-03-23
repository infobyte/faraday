// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
  .directive('d3Treemap', ['d3Service', 
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
            "left": parseInt(attrs.marginLeft) || 10,
          }

          function position() {
            this.style("left", function(d) { return d.x + "px"; })
              .style("top", function(d) { return d.y + "px"; })
              .style("width", function(d) { return Math.max(0, d.dx - 1) + "px"; })
              .style("height", function(d) { return Math.max(0, d.dy - 1) + "px"; });
          }

          scope.$watch('data', function(newData) {
            scope.render(newData);
          }, true);
 
          scope.render = function(data) {

            if (!data || data.length == 0) return;

          var width = data.width || 160,
            height = data.height || 133;

            var div = d3.select(ele[0])
              .append("div")
              .attr("class", "treemap")
              .attr("id", "treemap_container")
              .style("position", "relative")
              .style("width", width + "px")
              .style("height", height + "px")
              .style("left", margin.left + "px")
              .style("top", margin.top + "px");

            // we need to make a copy of the data, because the treemap is going to change it
            // and we have a watcher for that data to re-render the treemap, so we can enter
            // in a recursion loop
            var data_cp = {};
            angular.copy(data, data_cp);

            var treemap = d3.layout.treemap()
              .size([width - margin.left - margin.right, height - margin.top - margin.bottom])
              .sticky(true)
              .value(function(d) {return d.value});

            var node = div.datum(data_cp).selectAll(".node")
              .data(treemap.nodes)
            .enter().append("div")
              .attr("class", "node treemap-tooltip")
              .call(position)
              .style("background", function(d) { return d.color; })
              .style('opacity', 0)
              .text(function(d, i) {
                if(data.width){
                  var total = d3.sum(data.children, function(d){return d.value;});
                  return (d.key+ " ( " + d3.round(100* d.value / total, 1) + "% " + ")" ) ; 
                }
              })
              .on('mouseover', function(d){
                if (!data.width){
                  document.getElementById("treemapText").innerHTML = "<div style='background-color:" + d.color + "'>" + d.key + '</div>' + d.value;
                }else{
                  document.getElementById("treemapTextModel").innerHTML = "<div style='background-color:" + d.color + "'>" + d.key + '</div>' + d.value;
                }
              })
              .on('mouseleave', function(){
                document.getElementById("treemapText").innerHTML = "";
              })
              .transition()
                  .duration(1250)
                  .style('opacity', 1);

          };
        });
      }}
  }]);