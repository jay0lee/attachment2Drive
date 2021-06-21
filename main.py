from base64 import urlsafe_b64decode
from datetime import datetime
import json
from urllib.parse import urlencode, quote
import os

from flask import redirect
from google.auth.transport.requests import AuthorizedSession
import google.oauth2.credentials
import requests
from urllib3.fields import RequestField 
from urllib3.filepost import encode_multipart_formdata, choose_boundary


rules_sheet_id = '1NCaI5uY49xQqJUf9cEMgo9QCorRIaQLkErV4K2CVwdU'
rules_sheet_name = 'Rules'
refresh_token = '1//0d-6tYFRrtS3UCgYIARAAGA0SNwF-L9IrYvgF2Y_IE3klxOyyrXgXWrFddCM-fU783RVJ7app7wbr8GNefPfHZDiQ8vPzXFegV6g'
client_id = '669604920449-9vdd89egpo235uiepb8pj40s2257sbso.apps.googleusercontent.com'
client_secret = 'TMclZqeo17Uv6uP7AerQqxcw'
token_uri = 'https://oauth2.googleapis.com/token'
scope = 'https://mail.google.com/ https://www.googleapis.com/auth/drive'
redirect_uri = 'https://us-east4-attachment2drive.cloudfunctions.net/authorize'
base_query = 'has:attachment label:unread label:inbox'
ignore_files = [
    'smime.p7s',
    'signature.asc',
    ]


# Globals that live through a single instance run and thus act as a cache
req = None              # authorized requests session
user_email = None     # email address of authorized user
user_local = None
user_domain = None
seen_msg_ids = []     # messages we've already processed


def authorize(request):
    """Responds to any HTTP request.
    Args:
        request (flask.Request): HTTP request object.
    Returns:
        The response text or any set of values that can be turned into a
        Response object using
        `make_response <http://flask.pocoo.org/docs/1.0/api/#flask.Flask.make_response>`.
    """
    if code := request.args.get('code'):
        exch_params = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri,
        }
        resp = requests.post('https://oauth2.googleapis.com/token', exch_params)
        if refresh_token := resp.json().get('refresh_token'):
            return f'refresh_token: {refresh_token}'
    auth_params = {
        'scope': scope,
        'client_id': client_id,
        'access_type': 'offline',
        'prompt': 'consent',
        'redirect_uri': redirect_uri,
        'response_type': 'code',
    }
    auth_param = urlencode(auth_params)
    auth_url = f'https://accounts.google.com/o/oauth2/v2/auth?{auth_param}'
    return redirect(auth_url)

def watch(request):
    """Triggered from a message on a Cloud Pub/Sub topic.
    We don't actually care about the pubsub data, we'll do
    our own Gmail search thank you."""
    credentials = google.oauth2.credentials.Credentials(
      'access_token',
      refresh_token=refresh_token,
      token_uri=token_uri,
      client_id=client_id,
      client_secret=client_secret)
    httpc = AuthorizedSession(credentials)
    watch_params = {
      'labelIds': ['INBOX'],
      'labelFilterAction': 'include',
      'topicName': 'projects/attachment2drive/topics/gmail-watch',
    }
    watch_uri = f'https://gmail.googleapis.com/gmail/v1/users/me/watch'
    resp = httpc.post(watch_uri, watch_params)
    return ''
 
def get_rules():
    rng = 'Rules!A2:F'
    params = {
        'fields': 'values',
    }
    url = f'https://sheets.googleapis.com/v4/spreadsheets/{rules_sheet_id}/values/{rng}?{urlencode(params)}'
    return req.get(url).json().get('values', [])

def get_user_email():
    url = 'https://gmail.googleapis.com/gmail/v1/users/me/profile?fields=emailAddress'
    return req.get(url).json().get('emailAddress')

def get_or_create_drive_folder_id(name, parent_id='root'):
    params = {
        'corpora': 'allDrives',
        'includeItemsFromAllDrives': True,
        'supportsAllDrives': True,
        'q': f"name = '{name}' and '{parent_id}' in parents and mimeType = 'application/vnd.google-apps.folder'",
        'fields': 'files(id)',
        'maxResults': 1,
    }
    url = f'https://www.googleapis.com/drive/v3/files?{urlencode(params)}'
    resp = req.get(url).json()
    if resp.get('files'):
        folder_id = resp['files'][0]['id']
        print(f'got existing folder id {folder_id} named {name}')
        return folder_id 
    else:
        params = {
            'supportsAllDrives': True,
            'fields': 'id',
        }
        body = {
            'name': name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [parent_id,],
            'fields': 'id',
        }
        url = f'https://www.googleapis.com/drive/v3/files?{urlencode(params)}'
        resp = req.post(url, json=body).json()
        folder_id = resp.get('id')
        print(f'created folder id {folder_id} named {name}')
        return folder_id


def get_authorized_session():
    creds = google.oauth2.credentials.Credentials(
              'access_token',
              refresh_token=refresh_token,
              token_uri=token_uri,
              client_id=client_id,
              client_secret=client_secret)
    return AuthorizedSession(creds)

def gmail_pubsub(event, context):
    """Triggered from a message on a Cloud Pub/Sub topic.
    We don't actually care about the pubsub data, we'll do
    our own Gmail search thank you."""
    for k, v in os.environ.items():
        print(f'{k}: {v}')
    global req, user_email, user_local, user_domain
    if not req:
        req = get_authorized_session()
    if not user_email:
        user_email = get_user_email()
        user_local, user_domain = user_email.split('@')
    rules = get_rules()
    for (desc, dst_folder_id, trigger_type, trigger_keyword, subdirectory, domain_view) in rules:
        process_rule(desc, dst_folder_id, trigger_type, trigger_keyword, subdirectory, domain_view)
    
def process_rule(desc, dst_folder_id, trigger_type, trigger_keyword, subdirectory, domain_view):
    print(f'Running rule {desc}...')
    if trigger_type.upper() == 'POSTFIX':
        q = f'{base_query} to:({user_local}+{trigger_keyword}@{user_domain})'
    elif trigger_type.upper() == 'SENDER':
        q = f'{base_query} to:({trigger_keyword})'
    elif trigger_type.upper() == 'SUBJECT':
        q = f'{base_query} subject:("{trigger_keyword}")'
    else:
        q = base_query
    print(f'Query is: {q}')
    list_params = {
         'q': q,
         'includeSpamTrash': False,
         'fields': 'messages/id,resultSizeEstimate',
         }
    list_param = urlencode(list_params)
    list_uri = f'https://gmail.googleapis.com/gmail/v1/users/me/messages?{list_param}'
    resp = req.get(list_uri)
    try:
        msgs = resp.json().get('messages', [])
    except json.JSONDecodeError:
        print(f'ERROR on Gmail search: {resp.status_code} {resp.text}')
        msgs = []
    print(f'list returned {len(msgs)} messages...')
    for msg in msgs:
        msg_id = msg.get('id')
        if msg_id in seen_msg_ids:
            print(f'already seen msg id {msg_id}')
        else:
            try:
                upload_message(msg_id, dst_folder_id, subdirectory)
                modify_message(msg_id)
                seen_msg_ids.append(msg_id) 
            except requests.HTTPError as e:
                print('Error uploading to Drive: {e}')   
    return 'Success!'

def modify_message(msg_id):
    modify_url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/modify'
    body = {
        'removeLabelIds': ['INBOX', 'UNREAD'],
        }
    resp = req.post(modify_url, body)
    print(f'Modify status {resp.status_code}')

def upload_message(msg_id, dst_folder_id, subdirectory):
    """Get and store attachment from Message with given id.

    :param msg_id: ID of Message containing attachment.
    """
    print(f'processing msg id {msg_id}...')
    get_url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}'
    message = req.get(get_url).json()
    payload = message.get('payload', {})
    if subdirectory.upper() == 'SENDER':
        for header in payload.get('headers', []):
            if header.get('name') == 'From':
                subdirectory = header.get('value')
                target_directory = get_or_create_drive_folder_id(subdirectory, dst_folder_id)
                break
    elif subdirectory.upper() == 'DATE':
        subdirectory = datetime.today().strftime('%Y-%m-%d')
        target_directory = get_or_create_drive_folder_id(subdirectory, dst_folder_id)
    else:
        target_directory = dst_folder_id
    process_part(payload, msg_id, target_directory)

def process_part(part, msg_id, target_directory):
    if 'parts' in part:
        for sub_part in part['parts']:
            process_part(sub_part, msg_id, target_directory)
    else:
        filename = part.get('filename')
        if filename and filename not in ignore_files:
            if 'data' in part['body']:
                data = part['body']['data']
            else:
                att_id = part['body']['attachmentId']
                att_url = f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}/attachments/{att_id}'
                att = req.get(att_url).json()
                data = att['data']
            file_data = urlsafe_b64decode(data.encode('UTF-8'))
            mime_type = part['mimeType']
            upload_status = upload_file(filename, mime_type, file_data, target_directory)
            print(f'upload result: {upload_status}')
            return upload_status
        return 0


def upload_file(filename, mime_type, data, target_directory):
    metadata = {
      'mimeType': mime_type,
      'name': filename,
      'parents': [target_directory, ]
    }
    body, content_type = encode_media_related(metadata, data, mime_type)
    resp = req.post(
      'https://www.googleapis.com/upload/drive/v3/files',
      data=body,
      params={'uploadType': 'multipart'},
      headers={'Content-Type': content_type},
      )
    resp.raise_for_status() # throw error if we failed
    return resp.status_code


def encode_multipart_related(fields, boundary=None):
    if boundary is None:
        boundary = choose_boundary()

    body, _ = encode_multipart_formdata(fields, boundary)
    content_type = str('multipart/related; boundary=%s' % boundary)

    return body, content_type

def encode_media_related(metadata, media, media_content_type):
    rf1 = RequestField(
        name='placeholder',
        data=json.dumps(metadata),
        headers={'Content-Type': 'application/json; charset=UTF-8'},
    )
    rf2 = RequestField(
        name='placeholder2',
        data=media,
        headers={'Content-Type': media_content_type},
    )
    return encode_multipart_related([rf1, rf2])
