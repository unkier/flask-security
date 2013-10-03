
from sqlalchemy.orm import class_mapper
from werkzeug.datastructures import ImmutableDict

from ..datastore import SQLAlchemyDatastore
from .models import get_model_classes

BIT_MASKS = ImmutableDict({
    'view': 1,
    'create': 2,
    'edit': 4,
    'delete': 8,
    'undelete': 16,
    'operator': 32,
    'master': 64,
    'owner': 128
})

PERMISSION_MAP = {
    'view': [BIT_MASKS[k] for k in ('view', 'edit', 'operator', 'master', 'owner')],
    'create': [BIT_MASKS[k] for k in ('create', 'operator', 'master', 'owner')],
    'edit': [BIT_MASKS[k] for k in ('edit', 'operator', 'master', 'owner')],
    'delete': [BIT_MASKS[k] for k in ('delete', 'operator', 'master', 'owner')],
    'undelete': [BIT_MASKS[k] for k in ('undelete', 'operator', 'master', 'owner')],
    'operator': [BIT_MASKS[k] for k in ('operator', 'master', 'owner')],
    'master': [BIT_MASKS[k] for k in ('operator', 'master')],
    'owner': [BIT_MASKS['owner']],
}


class AclDatastore(SQLAlchemyDatastore):

    # options = {
    #     'oid_table_name': AclObjectIdentity.__tablename__,
    #     'class_table_name': AclClass.__tablename__,
    #     'oid_ancestors_table_name': AclObjectIdentityAncestor.__tablename__
    # }

    def __init__(self, db, *args, **kwargs):
        super(AclDatastore, self).__init__(db, *args, **kwargs)
        self.models = dict([(m.__name__, m) for m in get_model_classes(db)])

    # def _find_children_sql(self, obj, direct_children_only):
    #     if not direct_children_only:
    #         query = """
    #             SELECT o.object_identifier, c.class_type
    #             FROM %(oid_table_name)s as o
    #             INNER JOIN %(class_table_name)s as c ON c.id = o.class_id
    #             INNER JOIN %(oid_ancestors_table_name)s as a ON a.object_identity_id = o.id
    #             WHERE a.ancestor_id = %(object_id)s AND a.object_identity_id != a.ancestor_id
    #         """
    #     else:
    #         query = """
    #             SELECT o.object_identifier, c.class_type
    #             FROM %(oid_table_name)s as o
    #             INNER JOIN %(class_table_name)s as c ON c.id = o.class_id
    #             WHERE o.parent_object_identity_id = %(object_id)s
    #         """
    #     return query % dict(object_id=obj.id,
    #                         oid_table_name=self.models['AclObjectIdentity'].__tablename__,
    #                         class_table_name=self.models['AclObjectClass'].__tablename__,
    #                         oid_ancestors_table_name=self.models['AclObjectIdentityAncestor'].__tablename__,)

    # def find_children(self, obj, direct_children_only=False):
    #     sql = self._find_children_sql(obj, direct_children_only)
    #     print sql
    #     rv = self.models['AclObjectIdentity'].query.join('object_class', 'ancestors').\
    #         filter(self.models['AclObjectIdentityAncestor'].ancestor_id == obj.id).\
    #         filter(self.models['AclObjectIdentityAncestor'].object_identity_id != self.models['AclObjectIdentityAncestor'].ancestor_id)
    #     print rv

    def get_obj_identifier_for_object(self, obj):
        identifier_column = class_mapper(obj.__class__).primary_key[0].name
        identifier = getattr(obj, identifier_column, None)
        if identifier is None:
            raise ValueError('Could not determine primary key for %s instance' % class_name)
        return str(identifier)

    def get_obj_class_name_for_class(self, clazz):
        return clazz.__name__

    def get_obj_class_name_for_object(self, obj):
        return self.get_obj_class_name_for_class(obj.__class__)

    def new_obj_class_from_object(self, obj):
        name = self.get_obj_class_name_for_object(obj)
        return self.models['AclObjectClass'](name=name)

    def create_obj_class(self, name):
        rv = self.put(self.models['AclObjectClass'](name=name))
        self.commit()
        return rv

    def get_or_create_obj_class(self, name):
        return self.find_obj_class(name=name) or \
               self.create_obj_class(name)

    def get_or_create_obj_class_from_object(self, obj):
        return self.get_or_create_obj_class(obj.__class__.__name__)

    def find_obj_class(self, **kwargs):
        return self.models['AclObjectClass'].query.filter_by(**kwargs).first()

    def find_oid(self, **kwargs):
        return self.models['AclObjectIdentity'].query.filter_by(**kwargs).first()

    def find_oid_for_object(self, obj):
        return self.find_oid(identifier=self.get_obj_identifier_for_object(obj),
                             object_class=self.new_obj_class_from_object(obj))

    def create_oid(self, identifier, object_class):
        AclObjectIdentity = self.models['AclObjectIdentity']
        rv =  self.put(AclObjectIdentity(identifier=identifier, object_class=object_class))
        self.commit()
        return rv

    def create_oid_from_object(self, obj):
        identifier = self.get_obj_identifier_for_object(obj)
        object_class = self.get_or_create_obj_class_from_object(obj)
        return self.create_oid(identifier, object_class)

    def get_or_create_oid_from_object(self, obj):
        return self.find_oid_for_object(obj) or self.create_oid_from_object(obj)

    def find_sid(self, **kwargs):
        AclSecurityIdentity = self.models['AclSecurityIdentity']
        return AclSecurityIdentity.query.filter_by(**kwargs).first()

    def create_sid(self, identifier, username):
        AclSecurityIdentity = self.models['AclSecurityIdentity']
        rv = self.put(AclSecurityIdentity(identifier=identifier, username=username))
        self.commit()
        return rv

    def get_sid_from_user(self, user):
        return self.find_sid(identifier=user.id, username=user.email)

    def get_or_create_sid_from_user(self, user):
        return self.get_sid_from_user(user) or self.create_sid(identifier=user.id, username=user.email)

    def grant_access(self, user, obj, permissions):
        oid = self.get_or_create_oid_from_object(obj)
        sid = self.get_or_create_sid_from_user(user)

