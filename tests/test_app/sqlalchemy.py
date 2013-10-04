# -*- coding: utf-8 -*-

import sys
import os

sys.path.pop(0)
sys.path.insert(0, os.getcwd())

from flask import current_app, request
from werkzeug.local import LocalProxy

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, UserMixin, RoleMixin, \
     SQLAlchemyUserDatastore, current_user, login_required
from flask_security.acl import grant_object_access, grant_class_access
from flask_security.decorators import is_granted

from tests.test_app import create_app as create_base_app, populate_data, \
     add_context_processors

_security = LocalProxy(lambda: current_app.extensions['security'])

def populate_acl_data(db, User, Role, Post):
    matt = User.query.filter_by(email='matt@lp.com').first()
    joe = User.query.filter_by(email='joe@lp.com').first()
    dave = User.query.filter_by(email='dave@lp.com').first()

    matts_post = Post(body='matt@lp.com post content', author=matt)
    joes_post = Post(body='joe@lp.com post content', author=joe)
    daves_post = Post(body='dave@lp.com post content', author=dave)

    for m in matts_post, joes_post, daves_post:
        db.session.add(m)

    db.session.commit()

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
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'

    db = SQLAlchemy(app)

    roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

    class Role(db.Model, RoleMixin):
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(80), unique=True)
        description = db.Column(db.String(255))

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255), unique=True)
        password = db.Column(db.String(255))
        last_login_at = db.Column(db.DateTime())
        current_login_at = db.Column(db.DateTime())
        last_login_ip = db.Column(db.String(100))
        current_login_ip = db.Column(db.String(100))
        login_count = db.Column(db.Integer)
        active = db.Column(db.Boolean())
        confirmed_at = db.Column(db.DateTime())
        roles = db.relationship('Role', secondary=roles_users,
                                backref=db.backref('users', lazy='dynamic'))

    class Post(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        body = db.Column(db.String(255))
        author_id = db.Column(db.ForeignKey('user.id'))
        author = db.relationship('User', backref='posts')

    datastore = SQLAlchemyUserDatastore(db, User, Role, acl_datastore=True)
    app.security = Security(app, datastore=datastore, **kwargs)
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
        db.drop_all()
        db.create_all()
        populate_data(app.config.get('USER_COUNT', None))
        populate_acl_data(db, User, Role, Post)

    return app

if __name__ == '__main__':
    create_app({}).run()
