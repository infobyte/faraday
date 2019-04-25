// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

function(doc) {
    parent = doc.parent
    emit(parent, {'_id': doc._id, 'type': doc.type});
}