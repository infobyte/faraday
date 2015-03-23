// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

module.exports = function(config){
  config.set({

    basePath : './',

    files : [ 
      '../_attachments/script/jquery-1.11.2.js',
      '../_attachments/script/angular.js',
      // '../_attachments/script/angular-mocks.js',
      '../_attachments/script/angular-route.js',
      '../_attachments/script/angular-selection-model.js',
      '../_attachments/script/*bootstrap*.js',
      '../_attachments/scripts/app.js',
      '../_attachments/scripts/**/*.js',
      '../tests/faradayApp/components/**/*.js',
      '../_attachments/script/angular-file-upload-shim.js',
      '../_attachments/script/angular-file-upload.js'

    ],

    autoWatch : true,

    frameworks: ['jasmine'],

    browsers : ['Chrome'],

    plugins : [
            'karma-chrome-launcher',
            'karma-firefox-launcher',
            'karma-jasmine',
            'karma-junit-reporter'
            ],

    junitReporter : {
      outputFile: 'test_out/unit.xml',
      suite: 'unit'
    }

  });
};
