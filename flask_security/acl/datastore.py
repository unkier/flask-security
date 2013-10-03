
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

PERMISSION_MAP = ImmutableDict({
    'view': [BIT_MASKS[k] for k in ('view', 'edit', 'operator', 'master', 'owner')],
    'create': [BIT_MASKS[k] for k in ('create', 'operator', 'master', 'owner')],
    'edit': [BIT_MASKS[k] for k in ('edit', 'operator', 'master', 'owner')],
    'delete': [BIT_MASKS[k] for k in ('delete', 'operator', 'master', 'owner')],
    'undelete': [BIT_MASKS[k] for k in ('undelete', 'operator', 'master', 'owner')],
    'operator': [BIT_MASKS[k] for k in ('operator', 'master', 'owner')],
    'master': [BIT_MASKS[k] for k in ('operator', 'master')],
    'owner': [BIT_MASKS['owner']],
})


class AclDatastore(SQLAlchemyDatastore):

    def __init__(self, db, *args, **kwargs):
        super(AclDatastore, self).__init__(db, *args, **kwargs)
        self.models = dict([(m.__name__, m) for m in get_model_classes(db)])

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
        return self.get_or_create_obj_class(self.get_obj_class_name_for_object(obj))

    def get_or_create_obj_class_from_class(self, clazz):
        return self.get_or_create_obj_class(self.get_obj_class_name_for_class(clazz))

    def find_obj_class(self, **kwargs):
        return self.models['AclObjectClass'].query.filter_by(**kwargs).first()

    def find_oid(self, **kwargs):
        return self.models['AclObjectIdentity'].query.filter_by(**kwargs).first()

    def find_oid_for_object(self, obj):
        return self.find_oid(identifier=self.get_obj_identifier_for_object(obj),
                             object_class=self.get_or_create_obj_class_from_object(obj))

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

    def create_sid(self, user_id):
        AclSecurityIdentity = self.models['AclSecurityIdentity']
        rv = self.put(AclSecurityIdentity(user_id=user_id))
        self.commit()
        return rv

    def get_sid_from_user(self, user):
        return self.find_sid(user_id=user.id)

    def get_or_create_sid_from_user(self, user):
        return self.get_sid_from_user(user) or self.create_sid(user_id=user.id)

    def get_mask(self, permissions):
        mask = 0
        for p in permissions:
            if p not in BIT_MASKS:
                perms = ', '.join(BIT_MASKS.keys())
                raise ValueError('%s is an invalid permission. Valid choices are: %s' % (p, perms))
            mask = mask | BIT_MASKS[p]
        return mask

    def grant_object_access(self, user, obj, permissions):
        mask = self.get_mask(permissions)
        oid = self.get_or_create_oid_from_object(obj)
        sid = self.get_or_create_sid_from_user(user)

        AclEntry = self.models['AclEntry']
        entry = AclEntry.query.filter_by(object_identity=oid, security_identity=sid).first()

        if entry is None:
            entry = AclEntry(object_identity=oid, security_identity=sid, mask=mask)
        else:
            entry.mask |= mask

        self.put(entry)
        self.commit()
        return entry

    def revoke_object_access(self, user, obj, permissions):
        oid = self.get_or_create_oid_from_object(obj)
        sid = self.get_or_create_sid_from_user(user)

        AclEntry = self.models['AclEntry']
        entry = AclEntry.query.filter_by(object_identity=oid, security_identity=sid).first()

        if entry is None:
            return None

        entry.mask &= ~self.get_mask(permissions)

        self.put(entry)
        self.commit()
        return entry

    def grant_class_access(self, user, clazz, permissions):
        mask = self.get_mask(permissions)
        oc = self.get_or_create_obj_class_from_class(clazz)
        sid = self.get_or_create_sid_from_user(user)

        AclEntry = self.models['AclEntry']
        entry = AclEntry.query.filter_by(object_class=oc, security_identity=sid).first()

        if entry is None:
            entry = AclEntry(object_class=oc, security_identity=sid, mask=mask)
        else:
            entry.mask |= mask

        self.put(entry)
        self.commit()
        return entry

    def revoke_class_access(self, user, clazz, permissions):
        oc = self.get_or_create_obj_class_from_class(clazz)
        sid = self.get_or_create_sid_from_user(user)

        AclEntry = self.models['AclEntry']
        entry = AclEntry.query.filter_by(object_class=oc, security_identity=sid).first()

        if entry is None:
            return None

        entry.mask &= ~self.get_mask(permissions)

        self.put(entry)
        self.commit()
        return entry
