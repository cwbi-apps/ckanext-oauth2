# -*- coding: utf-8 -*-
"""
CKAN OAuth2 Extension DB Layer
"""

import sqlalchemy as sa
from ckan import model

UserToken = None

def init_db(model):
    """
    Initialize the user_token table and ORM mapping.
    Returns the UserToken class.
    """
    global UserToken
    if UserToken is None:

        class _UserToken(model.DomainObject):
            """
            ORM class for user_token table
            """
            @classmethod
            def by_user_name(cls, user_name):
                return model.Session.query(cls).filter_by(user_name=user_name).first()

        UserToken = _UserToken

        # Define table
        user_token_table = sa.Table(
            'user_token',
            model.meta.metadata,
            sa.Column('user_name', sa.types.UnicodeText, primary_key=True),
            sa.Column('access_token', sa.types.UnicodeText),
            sa.Column('token_type', sa.types.UnicodeText),
            sa.Column('refresh_token', sa.types.UnicodeText),
            sa.Column('expires_in', sa.types.UnicodeText)
        )

        # Bind to engine and create table if not exists
        user_token_table.create(bind=model.meta.engine, checkfirst=True)

        # Map ORM class
        model.meta.mapper(UserToken, user_token_table)

    return UserToken
