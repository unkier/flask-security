
from flask import current_app
from werkzeug.local import LocalProxy

from .datastore import SQLAlchemyDatastore, MongoEngineDatastore
from .utils import get_acl_class_id

_security = LocalProxy(lambda: current_app.extensions['security'])
_datastore = LocalProxy(lambda: _security.datastore.acl_datastore)

DEFAULT_BIT_MASKS = {
    'view': 1,
    'edit': 2,
    'create': 4,
    'delete': 8,
    'admin': 16,
    'owner': 32,
    'staff': 64
}

DEFAULT_PERMISSION_MAP = {
    'view': [DEFAULT_BIT_MASKS[k] for k in ('view', 'edit', 'admin', 'owner', 'staff')],
    'edit': [DEFAULT_BIT_MASKS[k] for k in ('edit', 'admin', 'owner', 'staff')],
    'create': [DEFAULT_BIT_MASKS[k] for k in ('create', 'admin', 'owner', 'staff')],
    'delete': [DEFAULT_BIT_MASKS[k] for k in ('delete', 'admin', 'owner', 'staff')],
    'admin': [DEFAULT_BIT_MASKS[k] for k in ('admin', 'owner', 'staff')],
    'owner': [DEFAULT_BIT_MASKS[k] for k in ('owner', 'staff')],
    'staff': [DEFAULT_BIT_MASKS['staff']],
}


class AclDatastore(object):

    def __init__(self, user_model, bit_masks=None, permission_map=None):
        self._model = self._get_entry_model(self.db, user_model)
        self._bit_masks = bit_masks or DEFAULT_BIT_MASKS
        self._permission_map = permission_map or DEFAULT_PERMISSION_MAP

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

    def get_bitmasks(self):
        return self._bit_masks

    def get_bitmask(self, name):
        bitmasks = self.get_bitmasks()
        try:
            return bitmasks[name]
        except KeyError:
            perms = ', '.join(bitmasks.keys())
            raise ValueError('%s is an invalid permission. Valid choices are: %s' % (name, perms))

    def get_masks_for_permission(self, permission):
        return self._permission_map[permission]

    def get_mask(self, *permissions):
        mask = 0
        for p in permissions:
            mask = mask | self.get_bitmask(p)
        return mask

    def grant_object_access(self, user, obj, permissions):
        AclEntry = self._model
        object_id = self.get_obj_id(obj)
        class_id = get_acl_class_id(obj.__class__)
        mask = self.get_mask(*permissions)
        entry = self.find_entry(object_id=object_id, class_id=class_id, user_id=user.id)

        if entry is None:
            entry = AclEntry(object_id=object_id, class_id=class_id, user_id=user.id, mask=mask)
        else:
            entry.mask |= mask

        return self._save_entry(entry)

    def grant_class_access(self, user, clazz, permissions):
        AclEntry = self._model
        class_id = get_acl_class_id(clazz)
        mask = self.get_mask(*permissions)

        entry = self.find_entry(class_id=class_id, user_id=user.id)

        if entry is None:
            entry = AclEntry(class_id=class_id, user_id=user.id, mask=mask)
        else:
            entry.mask |= mask

        return self._save_entry(entry)

    def revoke_object_access(self, user, obj, permissions):
        mask = self.get_mask(*permissions)
        object_id = self.get_obj_id(obj)
        class_id = get_acl_class_id(obj.__class__)
        entry = self.find_entry(object_id=object_id, class_id=class_id, user_id=user.id)
        return self._apply_revoke(entry, mask)

    def revoke_class_access(self, user, clazz, permissions):
        mask = self.get_mask(*permissions)
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

    def find_entry(self, object_id=None, class_id=None, user_id=None):
        from sqlalchemy import and_

        return self._model.query.filter(
            and_(
                self._model.object_id == object_id,
                self._model.class_id == class_id,
                self._model.user_id == user_id
            )
        ).first()

    def get_obj_id(self, obj):
        from sqlalchemy.orm import class_mapper

        primary_key_column = class_mapper(obj.__class__).primary_key[0].name
        obj_id = getattr(obj, primary_key_column, None)
        if obj_id is None:
            raise ValueError('Could not determine primary key for %s' % obj)
        return obj_id


class MongoEngineAclDatastore(MongoEngineDatastore, AclDatastore):

    def __init__(self, db, user_model):
        MongoEngineDatastore.__init__(self, db)
        AclDatastore.__init__(self, user_model)

    def _get_entry_model(self, db, user_model):
        class AclEntry(db.Document):
            mask = db.IntField()
            object_id = db.ObjectIdField()
            class_id = db.StringField(max_length=200)
            user_id = db.ObjectIdField()
        return AclEntry

    def find_entry(self, object_id=None, class_id=None, user_id=None):
        from mongoengine import Q
        query = Q(class_id=class_id) & Q(user_id=user_id)
        if object_id:
            query = Q(object_id=object_id) & query
        else:
            query = Q(object_id__exists=False) & query
        return self._model.objects(query).first()

    def get_obj_id(self, obj):
        return obj.id


def grant_object_access(*args, **kwargs):
    return _datastore.grant_object_access(*args, **kwargs)


def grant_class_access(*args, **kwargs):
    return _datastore.grant_class_access(*args, **kwargs)


def revoke_object_access(*args, **kwargs):
    return _datastore.revoke_object_access(*args, **kwargs)


def revoke_class_access(*args, **kwargs):
    return _datastore.revoke_class_access(*args, **kwargs)
