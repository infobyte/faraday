import pytest
from passlib.hash import pbkdf2_sha1
import import_users_from_couch

NON_ADMIN_DOC = {
    "_id": "org.couchdb.user:removeme2",
    "_rev": "0-00000000000000000000000000000000",
    "password_scheme": "pbkdf2",
    "iterations": 10,
    "name": "removeme2",
    "roles": [
        "pentester"
    ],
    "type": "user",
    "derived_key": "d2061cb98f85b5e14eda97da556c1625906e5c2b",
    "salt": "60604061640065389e9e90ca12c83b8d"
}

ADMIN_DOC = {
    "_id": "org.couchdb.user:removeme",
    "_rev": "1-00000000000000000000000000000000",
    "name": "removeme",
    "password": None,
    "roles": [],
    "type": "user"
}

def test_import_encrypted_password_from_admin_user():
    original_hash = ('-pbkdf2-eeea435c505e74d33a8c1b55c39d8dd355db4c2d,'
             'aedeef5a01f96a84360d2719fc521b9f,10')
    new_hash = import_users_from_couch.convert_couchdb_hash(original_hash)
    assert pbkdf2_sha1.verify('12345', new_hash)


def test_import_plaintext_password_from_admin_user():
    assert import_users_from_couch.convert_couchdb_hash('12345') == '12345'


def test_import_non_admin_from_document():
    new_hash = import_users_from_couch.get_hash_from_document(NON_ADMIN_DOC)
    assert pbkdf2_sha1.verify('12345', new_hash)


def test_import_admin_from_document_fails():
    with pytest.raises(ValueError):
        import_users_from_couch.get_hash_from_document(ADMIN_DOC)


def test_parse_all_docs_response_succeeds():
    doc_with_metadata = {
        "id": "org.couchdb.user:removeme",
        "key": "org.couchdb.user:removeme",
        "value": {"rev": "1-00000000000000000000000000000000"},
        "doc": ADMIN_DOC
    }
    data = {
        "total_rows": 15,
        "offset": 0,
        "rows": [doc_with_metadata] * 15
    }
    assert import_users_from_couch.parse_all_docs(data) == [ADMIN_DOC] * 15
