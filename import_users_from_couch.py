from __future__ import print_function
import argparse
import requests
from urlparse import urljoin

from binascii import unhexlify
from passlib.utils.binary import ab64_encode
from passlib.hash import pbkdf2_sha1

from flask_script import Manager
from server.web import app
from server.models import db


COUCHDB_USER_PREFIX = 'org.couchdb.user:'
COUCHDB_PASSWORD_PREXFIX = '-pbkdf2-'


def modular_crypt_pbkdf2_sha1(checksum, salt, iterations=1000):
    return '$pbkdf2${iterations}${salt}${checksum}'.format(
        iterations=iterations,
        salt=ab64_encode(salt),
        checksum=ab64_encode(unhexlify(checksum)),
    )


def convert_couchdb_hash(original_hash):
    if not original_hash.startswith(COUCHDB_PASSWORD_PREXFIX):
        # Should be a plaintext password
        return original_hash
    checksum, salt, iterations = original_hash[
        len(COUCHDB_PASSWORD_PREXFIX):].split(',')
    iterations = int(iterations)
    return modular_crypt_pbkdf2_sha1(checksum, salt, iterations)


def get_hash_from_document(doc):
    scheme = doc.get('password_scheme', 'unset')
    if scheme != 'pbkdf2':
        raise ValueError('Unknown password scheme: %s' % scheme)
    return modular_crypt_pbkdf2_sha1(doc['derived_key'], doc['salt'],
                                     doc['iterations'])


def parse_all_docs(doc):
    return [row['doc'] for row in doc['rows']]


def import_users(admins, all_users):

    manager = Manager(app)
    with app.app_context():

        # Import admin users
        for (username, password) in admins.items():
            print("Creating user", username)
            app.user_datastore.create_user(
                username=username,
                email=username + '@test.com',
                password=convert_couchdb_hash(password),
                is_ldap=False
            )

        # Import non admin users
        for user in all_users:
            if not user['_id'].startswith(COUCHDB_USER_PREFIX):
                # It can be a view or something other than a user
                continue
            if user['name'] in admins.keys():
                # This is an already imported admin user, skip
                continue
            print("Importing", user['name'])
            app.user_datastore.create_user(
                username=user['name'],
                email=user['name'] + '@test.com',
                password=get_hash_from_document(user),
                is_ldap=False
            )
        db.session.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--couch-url', default='http://localhost:5984')
    parser.add_argument('username')
    parser.add_argument('password')
    args = parser.parse_args()

    auth = (args.username, args.password)
    admins_url = urljoin(args.couch_url,
                         '/_config/admins')
    users_url = urljoin(args.couch_url,
                        '/_users/_all_docs?include_docs=true')
    import_users(requests.get(admins_url, auth=auth).json(),
                 parse_all_docs(requests.get(users_url, auth=auth).json()))
