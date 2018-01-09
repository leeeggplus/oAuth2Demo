# Django libraries
from django.shortcuts import render, redirect, render_to_response
from django.http import HttpResponse
# Python network/http/datetime libraries
import json
import datetime
from urllib import request as urllib_Request, parse as urllib_parse
from urllib.error import URLError, HTTPError, ContentTooShortError
# Apps
from apps.auth2.models import auth2



##################
# globals - Azure
# ################    
azure_client_id = 'e68115a7-0bd6-4696-98c7-dbba6d97bdef'
azure_redirect_uri = 'http://127.0.0.1:8000/auth2/home/'
azure_scope = 'offline_access Calendars.ReadWrite Contacts.ReadWrite Mail.ReadWrite Sites.ReadWrite.All User.ReadWrite.All'
azure_state_code = '19491001_Azure'
# authorization code
azure_authorization_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={0}&response_type=code&redirect_uri={1}&scope={2}&state={3}' 
azure_authorization_uri = azure_authorization_endpoint.format(azure_client_id, azure_redirect_uri, azure_scope, azure_state_code)
# token
azure_token_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
azure_client_secret = 'lG6971})fwggciDCBEZX5%:'
# outlook messages
azure_outlook_get_messages_uri = 'https://graph.microsoft.com/v1.0/users/{0}/messages'
azure_outlook_get_one_message_uri = 'https://graph.microsoft.com/v1.0//users/{0}/messages/{1}'
# admin user
azure_admin_get_one_user_uri = 'https://graph.microsoft.com/v1.0/users/{0}'
# spo list item
azure_spo_list_item_uri = 'https://graph.microsoft.com/v1.0/sites/{0}/lists/{1}/items/{2}'



# error handler
def error(request):
    '''
    Handler for error
    display error message
    '''
    error_message = request.session['error_message']

    context = {
        'error_message': error_message
    }

    return render(request, 'auth2/error.html', context)


# home
def home(request):
    '''
    Landing page for oAuth2 Demo
    request method equals GET and has parameter 'code' ---> Get Authorization Code 
    If no 'code' in request ---> common access to the landing page.
    ''' 
    azure_token_post_header = {
        'content-type': 'application/x-www-form-urlencoded',        
    }

    azure_token_post_data = {
        'client_id': azure_client_id,
        'scope': azure_scope,
        'redirect_uri': azure_redirect_uri,
        'grant_type': 'authorization_code',
        'client_secret': azure_client_secret,
    }

    if request.method == 'GET' and request.GET.get('code'):
        '''
        code exists in request
        add it into azure_token_post_data
        '''
        # Azure
        if request.GET.get('state') == azure_state_code:
            # retrieve access_token
            azure_token_post_data['code'] = request.GET['code']
            
            try: 
                data = urllib_parse.urlencode(azure_token_post_data).encode('utf-8')
                req = urllib_Request.Request(azure_token_endpoint, headers=azure_token_post_header, data=data)
                res = urllib_Request.urlopen(req).read()            
                resJson = json.loads(res.decode('utf-8'))

            except URLError:
                request.session['error_message'] = 'urllib.error.URLError'
                return redirect('auth2_error')     

            except HTTPError:
                request.session['error_message'] = 'urllib.error.HTTPError'
                return redirect('auth2_error')

            except ContentTooShortError:
                request.session['error_message'] = 'urllib.error.ContentTooShortError'
                return redirect('auth2_error')

            # create auth2 object            
            expires_at = datetime.datetime.now() + datetime.timedelta(seconds=resJson['expires_in'])
            auth2_obj = auth2.objects.filter(client_id=azure_client_id).first()            

            if not auth2_obj:
                auth2_obj = auth2(provider='Azure', client_id=azure_client_id, client_secret=azure_client_secret,
                                scope=azure_scope, token_type=resJson['token_type'], access_token=resJson['access_token'],
                                refresh_token=resJson['refresh_token'], expires_at=expires_at)              

            else:
                auth2_obj.access_token = resJson['access_token']
                auth2_obj.refresh_token = resJson['refresh_token']
                auth2_obj.expires_at = expires_at

            # Update auth2 object
            auth2_obj.save() 
            return redirect('auth2_azure')

        
        # Linkedin
        # Google

    context = {
        'azure_authorization_uri': azure_authorization_uri
    }
    return render(request, 'auth2/home.html', context)


# azure functions page
def azure(request):
    '''
    No user profile introduced.
    Suppose each provider has only one instance in the database.
    Thus get the first instance.
    '''
    auth2_obj = auth2.objects.filter(provider='Azure').first()
    # instance does not exist.
    # redirect back to home
    if not auth2_obj:
        return redirect('auth2_home')

    context = {
        'auth2_obj': auth2_obj
    }

    return render(request, 'auth2/azure.html', context)


# refresh token
def azure_refresh_token(request):
    '''
    refresh token for Azure
    '''
    auth2_obj = auth2.objects.filter(provider='Azure').first()

    azure_token_post_header = {
        'content-type': 'application/x-www-form-urlencoded',        
    }

    azure_token_post_data = {
        'client_id': azure_client_id,
        'scope': azure_scope,
        'redirect_uri': azure_redirect_uri,
        'grant_type': 'refresh_token',
        'client_secret': azure_client_secret,
        'refresh_token': auth2_obj.refresh_token,
    }
                
    try: 
        data = urllib_parse.urlencode(azure_token_post_data).encode('utf-8')
        req = urllib_Request.Request(azure_token_endpoint, headers=azure_token_post_header, data=data)
        res = urllib_Request.urlopen(req).read()            
        resJson = json.loads(res.decode('utf-8'))

    except URLError:
        request.session['error_message'] = 'urllib.error.URLError'
        return redirect('auth2_error')     

    except HTTPError:
        request.session['error_message'] = 'urllib.error.HTTPError'
        return redirect('auth2_error')

    except ContentTooShortError:
        request.session['error_message'] = 'urllib.error.ContentTooShortError'
        return redirect('auth2_error')

    auth2_obj.access_token = resJson['access_token']
    auth2_obj.refresh_token = resJson['refresh_token']
    auth2_obj.expires_at = datetime.datetime.now() + datetime.timedelta(seconds=resJson['expires_in'])
    # Update auth2 object
    auth2_obj.save() 

    return redirect('auth2_azure')


# Get Mails
def azure_read_messages(request):
    '''
    Read messages: DOC https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/resources/message
    request: https://graph.microsoft.com/v1.0/users/leeegg@madrix.onmicrosoft.com/messages
    method: GET
    '''
    # no check for if token has been expired
    upn = 'leeegg@madrix.onmicrosoft.com'

    auth2_obj = auth2.objects.filter(provider='Azure').first()
    messages_endpoint_uri = azure_outlook_get_messages_uri.format(upn)    
    token = 'Bearer {0}'.format(auth2_obj.access_token)

    headers = {
        'Authorization': token,
    }

    req = urllib_Request.Request(messages_endpoint_uri, headers=headers)
    res = urllib_Request.urlopen(req).read()
    resJson = json.loads(res.decode('utf-8'))

    mails = []
    for obj in resJson['value']:
        # compose mail obj
        if 'from' not in obj:
            continue

        mail = {
            'id': obj['id'],
            'subject': obj['subject'],            
            'from': obj['from']['emailAddress']['address'],
            'bodyPreview': obj['bodyPreview'],
        }

        mails.append(mail)


    context = {
        'mails': mails,
    }

    return render_to_response('auth2/mails.html', context)


# Get 1st Mail
def azure_read_first_message(request):
    '''
    Read messages: DOC https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/message_get
    request: https://graph.microsoft.com/v1.0/users/leeegg@madrix.onmicrosoft.com/messages/{id}
    {id} sample - HARD CODE: AAMkADk5YzNkNzZmLWE2MTUtNDgyYy04ZTY5LThiNmRlMmEzODQyMABGAAAAAAAcLmqIN4rmTImnVB8ajVq1BwArw6927qpCQ5YIddIav3tEAAAAAAEMAAArw6927qpCQ5YIddIav3tEAAHes9weAAA=
    method: GET
    '''
    upn = 'leeegg@madrix.onmicrosoft.com'
    message_id = 'AAMkADk5YzNkNzZmLWE2MTUtNDgyYy04ZTY5LThiNmRlMmEzODQyMABGAAAAAAAcLmqIN4rmTImnVB8ajVq1BwArw6927qpCQ5YIddIav3tEAAAAAAEMAAArw6927qpCQ5YIddIav3tEAAHes9weAAA='
    auth2_obj = auth2.objects.filter(provider='Azure').first()

    message_endpoint_uri = azure_outlook_get_one_message_uri.format(upn, message_id)
    token = 'Bearer {0}'.format(auth2_obj.access_token)

    headers = {
        'Authorization': token,
    }

    req = urllib_Request.Request(message_endpoint_uri, headers=headers)
    res = urllib_Request.urlopen(req).read()
    resJson = json.loads(res.decode('utf-8'))

    mail = {
        'id': resJson['id'],
        'subject': resJson['subject'],
        'from': resJson['from']['emailAddress']['address'],
        'receivedDateTime': resJson['receivedDateTime'],
        'body': resJson['body'],
    }

    context = {
        'mail': mail,
    }

    return render_to_response('auth2/mail.html', context)


# Get User
def azure_get_user(request):
    '''
    Get User: DOC https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/user_get
    request: https://graph.microsoft.com/v1.0/users/{id | userPrincipalName}
    {userPrincipalName} sample - HARD CODE: aliciakeys@Madrix.onmicrosoft.com
    method: GET
    '''
    upn = 'aliciakeys@Madrix.onmicrosoft.com'
    auth2_obj = auth2.objects.filter(provider='Azure').first()

    get_user_endpoint_uri = azure_admin_get_one_user_uri.format(upn)
    token = 'Bearer {0}'.format(auth2_obj.access_token)

    headers = {
        'Authorization': token,
    }

    req = urllib_Request.Request(get_user_endpoint_uri, headers=headers)
    res = urllib_Request.urlopen(req).read()
    resJson = json.loads(res.decode('utf-8'))    

    user = {
        'id': resJson['id'],
        'displayName': resJson['displayName'],
        'mail': resJson['mail'],
        'jobTitle': resJson['jobTitle'],
        'businessPhones': resJson['businessPhones'][0],
        'officeLocation': resJson['officeLocation'],
    }

    context = {
        'user': user,
    }

    return render_to_response('auth2/user.html', context)


# Get SPO list item
def azure_get_spo_list_item(request):
    '''
    Get SPO list item: DOC https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/listitem_get
    request: https://graph.microsoft.com/v1.0/sites/{site-id}/lists/{list-id}/items/{item-id}
    method: GET

    sample: "https://graph.microsoft.com/v1.0/sites/madrix.sharepoint.com, 24d5bf2e-b20b-4c53-8213-96d922da0cf7, 18c916b5-b56c-4b31-8df5-72a90a211d80/lists/7a33dfbd-d71b-49cb-b427-0bc8bfe093b5/items/1" 
    {site-id} sample - HARD CODE: "id": "madrix.sharepoint.com, 24d5bf2e-b20b-4c53-8213-96d922da0cf7, 18c916b5-b56c-4b31-8df5-72a90a211d80",
    {list-id} sample - HARD CODE: 7a33dfbd-d71b-49cb-b427-0bc8bfe093b5       
    '''
    site_id = 'madrix.sharepoint.com,24d5bf2e-b20b-4c53-8213-96d922da0cf7,18c916b5-b56c-4b31-8df5-72a90a211d80' #ensure NO space
    list_id = '7a33dfbd-d71b-49cb-b427-0bc8bfe093b5'
    item_id = '1'
    get_spo_list_item_endpoint_uri = azure_spo_list_item_uri.format(site_id, list_id, item_id)

    auth2_obj = auth2.objects.filter(provider='Azure').first()
    token = 'Bearer {0}'.format(auth2_obj.access_token)

    headers = {
        'Authorization': token,
    }
    
    req = urllib_Request.Request(get_spo_list_item_endpoint_uri, headers=headers)
    res = urllib_Request.urlopen(req).read()
    resJson = json.loads(res.decode('utf-8'))    

    item = {
        'id': resJson['id'],
        'createdDateTime': resJson['createdDateTime'],
        'webUrl': resJson['webUrl'],
        'title': resJson['fields']['Title'],
        'Author0': resJson['fields']['Author0'],
        'Interests': resJson['fields']['Interests'],
        'Country': resJson['fields']['Country'],
    }

    context = {
        'item': item,
    }

    return render_to_response('auth2/spo_list_item.html', context)
