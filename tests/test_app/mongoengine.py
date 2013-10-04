# -*- coding: utf-8 -*-

import sys
import os

sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask.ext.mongoengine import MongoEngine
from flask.ext.security import Security, UserMixin, RoleMixin, \
     MongoEngineUserDatastore, login_required, is_granted, \
     grant_object_access, grant_class_access

from tests.test_app import create_app as create_base_app, populate_data, \
     add_context_processors

def populate_acl_data(db, User, Role, Post):
    matt = User.objects(email='matt@lp.com').first()
    joe = User.objects(email='joe@lp.com').first()
    dave = User.objects(email='dave@lp.com').first()

    matts_post = Post(body='matt@lp.com post content', author=matt)
    joes_post = Post(body='joe@lp.com post content', author=joe)
    daves_post = Post(body='dave@lp.com post content', author=dave)

    for m in [matts_post, joes_post, daves_post]:
        m.save()

    grant_object_access(matt, matts_post, ['owner'])
    grant_object_access(joe, joes_post, ['owner'])
    grant_object_access(dave, daves_post, ['owner'])

    # Matt can edit any post
    grant_class_access(matt, Post, ['edit'])

    # Joe can edit and delete any post
    grant_class_access(joe, Post, ['edit', 'delete'])

    # dave can admin roles
    grant_class_access(dave, Role, ['admin'])

def create_app(config, **kwargs):
    app = create_base_app(config)

    app.config['MONGODB_SETTINGS'] = dict(
        db='flask_security_test',
        host='localhost',
        port=27017
    )

    db = MongoEngine(app)

    class Role(db.Document, RoleMixin):
        name = db.StringField(required=True, unique=True, max_length=80)
        description = db.StringField(max_length=255)

    class User(db.Document, UserMixin):
        email = db.StringField(unique=True, max_length=255)
        password = db.StringField(required=True, max_length=255)
        last_login_at = db.DateTimeField()
        current_login_at = db.DateTimeField()
        last_login_ip = db.StringField(max_length=100)
        current_login_ip = db.StringField(max_length=100)
        login_count = db.IntField()
        active = db.BooleanField(default=True)
        confirmed_at = db.DateTimeField()
        roles = db.ListField(db.ReferenceField(Role), default=[])

    class Post(db.Document):
        body = db.StringField()
        author = db.ReferenceField('User')

    datastore = MongoEngineUserDatastore(db, User, Role, acl_datastore=True)
    app.security = Security(app, datastore=datastore, **kwargs)
    app.Post = Post
    add_context_processors(app.security)

    # Editing and deleting is ACL controlled
    @app.route('/posts/<post_id>', methods=['PUT'])
    @login_required
    @is_granted(Post, 'edit')
    def edit_post(post_id):
        return 'Post updated successfully'

    @app.route('/posts/<post_id>', methods=['DELETE'])
    @login_required
    @is_granted(Post, 'delete')
    def del_post(post_id):
        return 'Post deleted successfully'

    @app.route('/roles', methods=['POST'])
    @login_required
    @is_granted(Role, 'create')
    def create_role():
        return 'Role created successfully'

    @app.route('/roles', methods=['PUT'])
    @login_required
    @is_granted(Role, 'edit')
    def edit_role():
        return 'Role updated successfully'

    @app.route('/roles', methods=['DELETE'])
    @login_required
    @is_granted(Role, 'delete')
    def del_role():
        return 'Role deleted successfully'

    @app.route('/roles')
    @login_required
    @is_granted(Role, 'owner')
    def get_role():
        return 'Owner operation success'

    @app.before_first_request
    def before_first_request():
        app.security.datastore.acl_datastore._model.drop_collection()
        User.drop_collection()
        Role.drop_collection()
        Post.drop_collection()
        populate_data(app.config.get('USER_COUNT', None))
        populate_acl_data(db, User, Role, Post)

    return app

if __name__ == '__main__':
    create_app({}).run()
