
from flask import current_app, request
from flask_principal import Permission
from sqlalchemy import and_
from sqlalchemy.orm import class_mapper
from werkzeug.datastructures import ImmutableDict
from werkzeug.local import LocalProxy

from .datastore import SQLAlchemyDatastore
from .utils import get_acl_class_id

_security = LocalProxy(lambda: current_app.extensions['security'])
_datastore = LocalProxy(lambda: _security.datastore.acl_datastore)

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


class AclDatastore(object):

    def __init__(self, user_model):
        self.AclEntry = self._get_entry_model(self.db, user_model)

    def _get_entry_model(self):
        raise NotImplementedError

    def _save_entry(self, entry):
        self.put(entry)
        self.commit()
        return entry

    def _apply_revoke(self, entry, mask):
        if entry is None:
            return None
        entry.mask &= ~mask
        return self._save_entry(entry)

    def find_entry(self, object_id=None, class_id=None, user_id=None):
        raise NotImplementedError

    def get_obj_id(self, obj):
        return obj.id

    def get_mask(self, permissions):
        mask = 0
        for p in permissions:
            if p not in BIT_MASKS:
                perms = ', '.join(BIT_MASKS.keys())
                raise ValueError('%s is an invalid permission. Valid choices are: %s' % (p, perms))
            mask = mask | BIT_MASKS[p]
        return mask

    def grant_object_access(self, user, obj, permissions):
        AclEntry = self.AclEntry
        object_id = self.get_obj_id(obj)
        class_id = get_acl_class_id(obj.__class__)
        mask = self.get_mask(permissions)
        entry = self.find_entry(object_id=object_id, class_id=class_id, user_id=user.id)

        if entry is None:
            entry = AclEntry(object_id=object_id, class_id=class_id, user_id=user.id, mask=mask)
        else:
            entry.mask |= mask

        return self._save_entry(entry)

    def grant_class_access(self, user, clazz, permissions):
        AclEntry = self.AclEntry
        class_id = get_acl_class_id(clazz)
        mask = self.get_mask(permissions)

        entry = self.find_entry(class_id=class_id, user_id=user.id)

        if entry is None:
            entry = AclEntry(class_id=class_id, user_id=user.id, mask=mask)
        else:
            entry.mask |= mask

        return self._save_entry(entry)

    def revoke_object_access(self, user, obj, permissions):
        mask = self.get_mask(permissions)
        object_id = self.get_obj_id(obj)
        class_id = get_acl_class_id(obj.__class__)
        entry = self.find_entry(object_id=object_id, class_id=class_id, user_id=user.id)
        return self._apply_revoke(entry, mask)

    def revoke_class_access(self, user, clazz, permissions):
        mask = self.get_mask(permissions)
        class_id = get_acl_class_id(clazz)
        entry = self.find_entry(class_id=class_id, user_id=user.id)
        return self._apply_revoke(entry, mask)


class SQLAlchemyAclDatastore(SQLAlchemyDatastore, AclDatastore):

    def __init__(self, db, user_model):
        SQLAlchemyDatastore.__init__(self, db)
        AclDatastore.__init__(self, user_model)

    def _get_entry_model(self, db, user_model):
        class AclEntry(db.Model):
            __tablename__ = 'acl_entries'
            id = db.Column(db.Integer, primary_key=True)
            mask = db.Column(db.Integer)
            object_id = db.Column(db.Integer, nullable=True)
            class_id = db.Column(db.String(200))
            user_id = db.Column(db.ForeignKey('%s.id' % user_model.__tablename__))
            user = db.relationship(user_model.__name__,
                                   backref=db.backref('acl_entries', lazy='dynamic'))
        return AclEntry

    def find_entry(self, object_id=None, class_id=None, user_id=None, mask=None):
        statements = [self.AclEntry.object_id == object_id,
                      self.AclEntry.class_id == class_id,
                      self.AclEntry.user_id == user_id]

        if mask:
            statements.append(self.AclEntry.mask.op('&')(mask) != 0)

        return self.AclEntry.query.filter(and_(*statements)).first()

    def get_obj_id(self, obj):
        primary_key_column = class_mapper(obj.__class__).primary_key[0].name
        obj_id = getattr(obj, primary_key_column, None)
        if obj_id is None:
            raise ValueError('Could not determine primary key for %s' % obj)
        return obj_id


class ObjectPermission(Permission):
    def __init__(self, permissions, model, view_arg, **kwargs):
        self.permissions = permissions
        self.model = model
        self.view_arg = view_arg

    def allows(self, identity):
        object_id = request.view_args.get(self.view_arg)
        class_id = get_acl_class_id(self.model)
        mask = _datastore.get_mask(self.permissions)
        entry = _datastore.find_entry(object_id=object_id, class_id=class_id, user_id=identity.id, mask=mask)
        return entry is not None


class ClassPermission(Permission):
    def __init__(self, permissions, model, **kwargs):
        self.permissions = permissions
        self.model = model

    def allows(self, identity):
        class_id = get_acl_class_id(self.model)
        mask = _datastore.get_mask(self.permissions)
        entry = _datastore.find_entry(class_id=class_id, user_id=identity.id, mask=mask)
        return entry is not None


def grant_object_access(*args, **kwargs):
    return _datastore.grant_object_access(*args, **kwargs)


def grant_class_access(*args, **kwargs):
    return _datastore.grant_class_access(*args, **kwargs)


def revoke_object_access(*args, **kwargs):
    return _datastore.revoke_object_access(*args, **kwargs)


def revoke_class_access(*args, **kwargs):
    return _datastore.revoke_class_access(*args, **kwargs)
