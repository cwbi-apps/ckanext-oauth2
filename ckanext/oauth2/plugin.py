# -*- coding: utf-8 -*-
"""
CKAN OAuth2 Plugin
"""

from __future__ import unicode_literals
import os
import logging
from functools import partial
from flask import Blueprint, redirect
from ckan import plugins
from ckan.common import g, current_user
from ckan.plugins import toolkit

from ckanext.oauth2 import oauth2, db
from ckanext.oauth2.controller import OAuth2Controller

log = logging.getLogger(__name__)

# ----------------------
# Auth function overrides
# ----------------------
def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}

@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    return _no_permissions(context, "Users cannot be created.")

@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    return _no_permissions(context, "Users cannot be edited.")

@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    return _no_permissions(context, "Users cannot reset passwords.")

@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    return _no_permissions(context, "Users cannot reset passwords.")


# ----------------------
# OAuth2 Plugin Class
# ----------------------
class OAuth2Plugin(plugins.SingletonPlugin):

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None, *args, **kwargs):
        log.debug("Initializing OAuth2 plugin")
        self.name = name  # <-- CKAN expects this
        self.oauth2helper = None
        self.register_url = None
        self.reset_url = None
        self.edit_url = None
        self.authorization_header = 'authorization'

    # ----------------------
    # CKAN Blueprint routes
    # ----------------------
    def get_blueprint(self):
        blueprint = Blueprint('ckanext_oauth2', __name__)

        @blueprint.route('/user/login')
        def login():
            return OAuth2Controller().login()

        @blueprint.route('/oauth2/callback')
        def callback():
            return OAuth2Controller().callback()

        if self.register_url:
            @blueprint.route('/user/register')
            def redirect_register():
                return redirect(self.register_url)

        if self.reset_url:
            @blueprint.route('/user/reset')
            def redirect_reset():
                return redirect(self.reset_url)

        if self.edit_url:
            @blueprint.route('/user/edit/<user>')
            def redirect_edit(user):
                return redirect(self.edit_url)

        return blueprint
    
    def update_config(self, config):
        """IConfigurer hook to update CKAN config"""
        import os
        self.register_url = os.environ.get(
            "CKAN_OAUTH2_REGISTER_URL",
            config.get('ckan.oauth2.register_url', None)
        )
        self.reset_url = os.environ.get(
            "CKAN_OAUTH2_RESET_URL",
            config.get('ckan.oauth2.reset.url', None)
        )
        self.edit_url = os.environ.get(
            "CKAN_OAUTH2_EDIT_URL",
            config.get('ckan.oauth2.edit.url', None)
        )
        self.authorization_header = os.environ.get(
            "CKAN_OAUTH2_AUTHORIZATION_HEADER",
            config.get('ckan.oauth2.authorization_header', 'Authorization')
        ).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths
        plugins.toolkit.add_template_directory(config, 'templates')
    # ----------------------
    # Identify current user
    # ----------------------
    def identify(self):
        def _refresh_and_save_token(user_name):
            new_token = self.oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, '')
        user_name = None

        # Handle Bearer token
        if self.authorization_header == "authorization" and apikey.startswith('Bearer '):
            apikey = apikey[7:].strip()

        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = self.oauth2helper.identify(token)
            except Exception:
                log.warning("OAuth2 token identification failed")

        # Fallback t
