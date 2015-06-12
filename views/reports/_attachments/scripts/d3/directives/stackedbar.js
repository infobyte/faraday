// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

angular.module('faradayApp')
    .directive('d3HorizontalStackedBar', ['d3Service', '$window', '$compile',
        function(d3Service, $window, $compile) {
            return {
                restrict: 'EA',
                scope: {
                    data: '=data'
                },
                link: function(scope, ele, attrs) {
                    d3Service.d3().then(function(d3) {
                        // update scope when changes occur
                        scope.$watch('data', function(newData) {
                            if(newData != undefined) scope.render(newData);
                        }, true);

                        // redraw graphic when resize occurs
                        angular.element($window).on('resize', function(e) {
                            if(scope.data != undefined) scope.render(scope.data);
                        });

                    }); // d3Service.d3()

                    scope.render = function(data) {
                        d3.select('.stackedbars').selectAll('svg').remove();

                        var margins = {
                            top: 12,
                            left: 24,
                            right: 12,
                            bottom: 12
                        };

                        // get parent width to calculate graphic width
                        var pwidth = ele.parent().width(),
                        width = pwidth * 0.9,
                        height = 80 - margins.top - margins.bottom;

                        var dataset = data.map(function(d) {
                                return [{
                                    k: d.key,
                                    c: d.color,
                                    y: d.value,
                                    x: 0
                                }];
                        });

                        stack = d3.layout.stack();
                        stack(dataset);

                        var dataset = dataset.map(function (group) {
                            return group.map(function (d) {
                                // Invert the x and y values, and y0 becomes x0
                                return {
                                    k: d.k,
                                    c: d.c,
                                    x: d.y,
                                    y: d.x,
                                    x0: d.y0
                                };
                            });
                        }),
                        svg = d3.select(".stackedbars")
                            .append('svg')
                            .attr('width', width + margins.left + margins.right)
                            .attr('height', height + margins.top + margins.bottom)
                            .append('g')
                            .attr('transform', 'translate(' + margins.left + ',' + margins.top + ')'),
                        xMax = d3.max(dataset, function (group) {
                            return d3.max(group, function (d) {
                                return d.x + d.x0;
                            });
                        }),
                        xScale = d3.scale.linear()
                            .domain([0, xMax])
                            .range([0, width]),
                        months = dataset[0].map(function (d) {
                            return d.y;
                        }),
                        yScale = d3.scale.ordinal()
                            .domain(months)
                            .rangeRoundBands([0, height], .1),
                        xAxis = d3.svg.axis()
                            .scale(xScale)
                            .orient('bottom'),
                        yAxis = d3.svg.axis()
                            .scale(yScale)
                            .orient('left'),
                        groups = svg.selectAll('g')
                            .data(dataset)
                            .enter()
                            .append('g')
                            .style('fill', function (d, i) {
                            return d[0].c;
                        }),
                        rects = groups.selectAll('rect')
                            .data(function (d) {
                                return d;
                            })
                            .enter()
                            .append('rect')
                            .attr('x', function (d) {
                                return xScale(d.x0);
                            })
                            .attr('y', function (d, i) {
                                return yScale(d.y);
                            })
                            .attr('height', function (d) {
                                return yScale.rangeBand();
                            })
                            .attr('width', function (d) {
                                return xScale(d.x);
                            })
                            .attr('tooltip-append-to-body', true)
                            .attr('tooltip', function(d) {
                                return d.k + " sums $" + d.x;
                            });

                        ele.removeAttr("d3-horizontal-stacked-bar");
                        $compile(ele)(scope);
                    }; // scope.render definition
                }
            };
        }]);
