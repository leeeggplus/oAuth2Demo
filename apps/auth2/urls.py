from django.urls import path
from apps.auth2.views import home, error, azure, azure_refresh_token, azure_read_messages, \
                             azure_read_first_message, azure_get_user, azure_get_spo_list_item, \
                             flow

urlpatterns= [    
    path('home/', home, name='auth2_home'),
    path('flow/', flow, name='auth2_flow'),    
    path('error/', error, name='auth2_error'),    
    path('azure/', azure, name='auth2_azure'),
    path('azure_refresh_token/', azure_refresh_token, name='auth2_azure_refresh_token'),
    path('azure_read_messages/', azure_read_messages, name='auth2_azure_read_messages'),
    path('azure_read_first_message/', azure_read_first_message, name='auth2_azure_read_first_message'),
    path('azure_get_user/', azure_get_user, name='auth2_azure_get_user'),
    path('azure_get_spo_list_item/', azure_get_spo_list_item, name='auth2_azure_get_spo_list_item'),
];