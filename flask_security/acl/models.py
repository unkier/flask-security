
from sqlalchemy import Table, Column, ForeignKey
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import relationship
from sqlalchemy.types import Boolean, Integer, String


class _AclObjectClass(object):
    id = Column('id', Integer, primary_key=True)
    name = Column('name', String(200))

    @declared_attr
    def __tablename__(cls):
        return 'acl_object_classes'


class _AclSecurityIdentity(object):
    id = Column('id', Integer, primary_key=True)
    identifier = Column('identifier', String(200))
    username = Column('username', Boolean)

    @declared_attr
    def __tablename__(cls):
        return 'acl_security_identities'


class _AclObjectIdentity(object):
    id = Column('id', Integer, primary_key=True)
    identifier = Column('identifier', String(100))
    entries_inheriting = Column('entries_inheriting', Boolean)

    @declared_attr
    def object_class_id(self):
        return Column('object_class_id', ForeignKey('acl_object_classes.id'))

    @declared_attr
    def object_class(cls):
        return relationship('AclObjectClass')

    @declared_attr
    def parent_id(cls):
        return Column('parent_object_identity_id', ForeignKey('acl_object_identities.id'), nullable=True)

    @declared_attr
    def parent(cls):
        return relationship('AclObjectIdentity')

    @declared_attr
    def __tablename__(cls):
        return 'acl_object_identities'


class _AclObjectIdentityAncestor(object):
    id = Column(Integer, primary_key=True)

    @declared_attr
    def object_identity_id(cls):
        return Column('object_identity_id', ForeignKey('acl_object_identities.id'))

    @declared_attr
    def ancestor_id(cls):
        return Column('ancestor_id', ForeignKey('acl_object_identities.id'))

    @declared_attr
    def __tablename__(cls):
        return 'acl_object_identity_ancestors'

    # object_identity = relationship('AclObjectIdentity', foreign_keys=object_identity_id)
    # ancestor = relationship('AclObjectIdentity', foreign_keys=ancestor_id)


class _AclEntry(object):
    id = Column(Integer, primary_key=True)
    field_name = Column(String(50))
    ace_order = Column(Integer)
    mask = Column(Integer)
    granting = Column(Boolean)
    granting_strategy = Column(String(30))
    audit_success = Column(Boolean)
    audit_failure = Column(Boolean)

    @declared_attr
    def class_id(cls):
        Column(ForeignKey('acl_object_classes.id'))

    @declared_attr
    def object_identity_id(cls):
        return Column(ForeignKey('acl_object_identities.id'), nullable=True)

    @declared_attr
    def security_identity_id(cls):
        return Column(ForeignKey('acl_security_identities.id'))

    @declared_attr
    def __tablename__(cls):
        return 'acl_entries'

    # clazz = relationship('AclObjectClass')
    # object_identity = relationship('AclObjectIdentity')
    # security_identity = relationship('AclSecurityIdentity')

def get_model_classes(db):
    bases = [_AclObjectClass, _AclSecurityIdentity, _AclObjectIdentity, _AclObjectIdentityAncestor, _AclEntry]
    return [type(c.__name__[1:], (db.Model, c), {}) for c in bases]

