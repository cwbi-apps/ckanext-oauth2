# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.


from __future__ import unicode_literals

import base64
import ckan.model as model
import ckan.lib.helpers as h
from flask import redirect, request
from flask_login import login_user
from . import db, constants
import json
import logging
from six.moves.urllib.parse import urljoin
import os
from urllib.parse import urlparse, parse_qs

from base64 import b64encode, b64decode
from ckan.plugins import toolkit
from oauthlib.oauth2 import InsecureTransportError
import requests
from requests_oauthlib import OAuth2Session
import six



log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(json.dumps({constants.CAME_FROM_FIELD: url}).encode('utf-8'))


def get_came_from(state):
    return json.loads(b64decode(state)).get(constants.CAME_FROM_FIELD, '/')


REQUIRED_CONF = ("authorization_endpoint", "token_endpoint", "client_id", "client_secret", "profile_api_url", "profile_api_user_field", "profile_api_mail_field")


class OAuth2Helper(object):

    def __init__(self):

        self.verify_https = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', '') == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.legacy_idm = six.text_type(os.environ.get('CKAN_OAUTH2_LEGACY_IDM', toolkit.config.get('ckan.oauth2.legacy_idm', ''))).strip().lower() in ("true", "1", "on")
        self.authorization_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_AUTHORIZATION_ENDPOINT', toolkit.config.get('ckan.oauth2.authorization_endpoint', ''))).strip()
        self.token_endpoint = six.text_type(os.environ.get('CKAN_OAUTH2_TOKEN_ENDPOINT', toolkit.config.get('ckan.oauth2.token_endpoint', ''))).strip()
        self.profile_api_url = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_URL', toolkit.config.get('ckan.oauth2.profile_api_url', ''))).strip()
        self.client_id = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_ID', toolkit.config.get('ckan.oauth2.client_id', ''))).strip()
        self.client_secret = six.text_type(os.environ.get('CKAN_OAUTH2_CLIENT_SECRET', toolkit.config.get('ckan.oauth2.client_secret', ''))).strip()
        self.scope = six.text_type(os.environ.get('CKAN_OAUTH2_SCOPE', toolkit.config.get('ckan.oauth2.scope', ''))).strip()
        self.rememberer_name = six.text_type(os.environ.get('CKAN_OAUTH2_REMEMBER_NAME', toolkit.config.get('ckan.oauth2.rememberer_name', 'auth_tkt'))).strip()
        self.profile_api_user_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_USER_FIELD', toolkit.config.get('ckan.oauth2.profile_api_user_field', ''))).strip()
        self.profile_api_fullname_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_FULLNAME_FIELD', toolkit.config.get('ckan.oauth2.profile_api_fullname_field', ''))).strip()
        self.profile_api_mail_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_MAIL_FIELD', toolkit.config.get('ckan.oauth2.profile_api_mail_field', ''))).strip()
        self.profile_api_groupmembership_field = six.text_type(os.environ.get('CKAN_OAUTH2_PROFILE_API_GROUPMEMBERSHIP_FIELD', toolkit.config.get('ckan.oauth2.profile_api_groupmembership_field', ''))).strip()
        self.sysadmin_group_name = six.text_type(os.environ.get('CKAN_OAUTH2_SYSADMIN_GROUP_NAME', toolkit.config.get('ckan.oauth2.sysadmin_group_name', ''))).strip()

        self.redirect_uri = urljoin(urljoin(toolkit.config.get('ckan.site_url', 'http://localhost:5000'), toolkit.config.get('ckan.root_path')), constants.REDIRECT_URL)

        # Init db
        db.init_db(model)

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from_url):
        # This function is called by the log in function when the user is not logged in

        log.debug('Challenge came_from_url: {0}'.format(came_from_url))
        if not came_from_url:
            came_from_url = '/'
        state = generate_state(came_from_url)

        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope, state=state)
        auth_url, _ = oauth.authorization_url(self.authorization_endpoint)
        log.debug('Challenge: Redirecting challenge to page {0}'.format(auth_url))
        return toolkit.redirect_to(auth_url)

    def get_token(self):

        oauth = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri, scope=self.scope)

        # Just because of FIWARE Authentication
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers['Authorization'] = 'Basic %s' % base64.urlsafe_b64encode(
                '%s:%s' % (self.client_id, self.client_secret)
            )
        
        # Extract authorization code from callback URL
        url_query = urlparse(toolkit.request.url).query
        code = parse_qs(url_query).get('code')[0]
 
        try:
            token = oauth.fetch_token(self.token_endpoint,
                                      headers=headers,
                                      code=code,
                                      client_secret=self.client_secret,
                                      authorization_response=toolkit.request.url,
                                      verify=self.verify_https)
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise
        except Exception as e:
            log.error(f"Unexpected error: {e}")
            raise

        return token

    def identify(self, token):
        try:
            if self.legacy_idm:
                profile_response = requests.get(self.profile_api_url + '?access_token=%s' % token['access_token'], verify=self.verify_https)
            else:
                oauth = OAuth2Session(self.client_id, token=token)
                profile_response = oauth.get(self.profile_api_url, verify=self.verify_https)

        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise

        # Token can be invalid
        if not profile_response.ok:
            error = profile_response.json()
            if error.get('error', '') == 'invalid_token':
                raise ValueError(error.get('error_description'))
            else:
                profile_response.raise_for_status()
        else:
            user_data = profile_response.json()
            email = user_data[self.profile_api_mail_field]
            user_name = user_data[self.profile_api_user_field]

            # In CKAN can exists more than one user associated with the same email
            # Some providers, like Google and FIWARE only allows one account per email
            user = model.User.by_email(email)

            # check for valid email
            # if not check_valid_emails(email):
            #     log.warning("OAuth2 login blocked: unauthorized email %s", email)
            #     return None

            # If the user does not exist, we have to create it...
            if user is None:
                user = model.User(email=email)

            # Now we update his/her user_name with the one provided by the OAuth2 service
            # In the future, users will be obtained based on this field
            user.name = user_name

            # Update fullname
            if self.profile_api_fullname_field != "" and self.profile_api_fullname_field in user_data:
                user.fullname = user_data[self.profile_api_fullname_field]

            # Update sysadmin status
            if self.profile_api_groupmembership_field != "" and self.profile_api_groupmembership_field in user_data:
                user.sysadmin = self.sysadmin_group_name in user_data[self.profile_api_groupmembership_field]

            # Save the user in the database
            model.Session.add(user)
            model.Session.commit()
            model.Session.remove()

            return user.name

    def _get_rememberer(self, environ):
        plugins = environ.get('repoze.who.plugins', {})

        return plugins.get(self.rememberer_name)

    # def remember(self, user_name):
    #     '''
    #     Remember the authenticated identity.

    #     This method simply delegates to another IIdentifier plugin if configured.
    #     '''
    #     log.debug('Repoze OAuth remember')
    #     environ = toolkit.request.environ
    #     rememberer = self._get_rememberer(environ)
    #     identity = {'repoze.who.userid': user_name}
    #     headers = rememberer.remember(environ, identity)
    #     for header, value in headers:
    #         toolkit.response.headers.add(header, value)

    def remember(self, user_name):
        log.debug('Flask-Login user: %s', user_name)
    
        # Load the user object from the database
        user = model.User.get(user_name)

        if user is None:
            log.error('User not found: %s', user_name)
            return

        # Log in the user using Flask-Login
        login_user(user)
        
        # add_user_to_orgs(user)
        

    def redirect_from_callback(self):
        '''Redirect to the callback URL after a successful authentication.'''
        state = request.args.get('state')  # replaces toolkit.request.params.get()
        came_from = get_came_from(state)
        return redirect(came_from, code=302)

    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                'access_token': user_token.access_token,
                'refresh_token': user_token.refresh_token,
                'expires_in': user_token.expires_in,
                'token_type': user_token.token_type
            }

    def update_token(self, user_name, token):
        if not user_name:
            log.warning("Skipping token update because user_name is None (invalid email login blocked).")
            return
        user_token = db.UserToken.by_user_name(user_name=user_name)
        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name
        # Save the new token
        user_token.access_token = token['access_token']
        user_token.token_type = token['token_type']
        user_token.refresh_token = token.get('refresh_token')
        user_token.expires_in = token['expires_in']
        model.Session.add(user_token)
        model.Session.commit()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            try:
                token = client.refresh_token(self.token_endpoint, client_secret=self.client_secret, client_id=self.client_id, verify=self.verify_https)
            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            self.update_token(user_name, token)
            log.info('Token for user %s has been updated properly' % user_name)
            return token
        else:
            log.warn('User %s has no refresh token' % user_name)

def add_user_to_orgs(user):
    try:
        # Check if the user is already a member of any org
        existing_orgs = [
            m.group_id for m in model.Session.query(model.Member)
            .filter_by(table_id=user.id, table_name='user', capacity='member')
        ]

        if existing_orgs:
            log.debug("User %s already in org(s) %s, skipping auto-add", user.name, existing_orgs)
            return

        # Split email
        email_parts = user.name.split('@')
        # if len(email_parts) != 2:
        #     log.warning("Skipping malformed username/email: %s", user.name)
        #     return

        user_domain = email_parts[1]

        # Get all orgs
        all_orgs = toolkit.get_action('organization_list')({}, {'all_fields': True, 'include_extras': True})
        top_org_ids = {org['id'] for org in all_orgs}  

        for org in all_orgs:
            #log.info ('org id: {}, org domain: {}'.format(org['id'], org.get('email_domain')))
            if org['id'] not in top_org_ids or not org.get('email_domain'):
                continue

            domain = org['email_domain']
            domain_parts = domain.split('.')

            match = (
                domain == user_domain
                or user_domain.endswith(f".{domain}")
                or domain.endswith(f".{user_domain}")
                or (
                    len(domain_parts) == 2 and
                    f"{domain_parts[0]}.mil.{domain_parts[1]}" in user_domain
                )
            )

            if match:
                log.info("Adding user %s to org %s", user.name, org['id'])
                context = {'ignore_auth': True}
                toolkit.get_action('organization_member_create')(
                    context, {'id': org['id'], 'username': user.name, 'role': 'member'}
                )

    except Exception as e:
        log.error("Error assigning user %s to org: %s", user.name, e, exc_info=True)

def check_valid_emails(user_name):
    # Split email
    email_parts = user_name.split('@')
    if len(email_parts) != 2:
        log.warning("Skipping malformed username/email: %s", user_name)
        return False   # invalid email

    user_domain = email_parts[1]

    # Get all orgs
    all_orgs = toolkit.get_action('organization_list')(
        {}, {'all_fields': True, 'include_extras': True}
    )
    top_org_ids = {org['id'] for org in all_orgs}

    matched = False
    log.info("in check valid email")
    for org in all_orgs:
        org_domain = org.get('email_domain')

        # Skip orgs without domain
        if org['id'] not in top_org_ids or not org_domain:
            continue

        domain_parts = org_domain.split('.')

        # Matching rules
        match = (
            org_domain == user_domain
            or user_domain.endswith(f".{org_domain}")
            or org_domain.endswith(f".{user_domain}")
            or (
                len(domain_parts) == 2 and
                f"{domain_parts[0]}.mil.{domain_parts[1]}" in user_domain
            )
        )

        # If matched, add user to org
        if match:
            matched = True
            log.info("User %s matched domain for org %s", user_name, org['id'])

    return matched   
