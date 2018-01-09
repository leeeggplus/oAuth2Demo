$(document).ready(function() {
    // event for loading all mails.
    $('#ReadMails').click(function() {
        $.get('/auth2/azure_read_messages/', function(data){
            $('#OutlookOperations').after(data);
        }); 
    });

    // event for loading single mail
    $('#Read1stMail').click(function() {
        $.get('/auth2/azure_read_first_message/', function(data){
            $('#OutlookOperations').after(data);
        }); 
    });

    // event for clear outlook mails
    $('#ClearMail').click(function() {
        $('#OutlookMails').remove();
    });

    // event for loading single user
    $('#GetUser').click(function() {
        $.get('/auth2/azure_get_user/', function(data){
            $('#UserOperations').after(data);
        }); 
    });

    // event for clear users
    $('#ClearUser').click(function() {
        $('#User').remove();
    });
});