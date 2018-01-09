from django.db import models

# Create your models here.
class auth2(models.Model):
    '''
    store auth2 information
    '''
    PROVIDER_CHOICES = (
        ('Azure', 'Azure'), 
        ('Google', 'Google'), 
        ('Linkedin', 'Linkedin'),
    )

    provider = models.CharField(max_length=50, choices=PROVIDER_CHOICES)
    client_id = models.CharField(max_length=50, unique=True, null=False, blank=False)
    client_secret = models.CharField(max_length=50, unique=True, null=False, blank=False)
    scope = models.TextField(max_length=2000)
    token_type = models.CharField(max_length=50)
    access_token = models.TextField(max_length=2000)
    refresh_token = models.TextField(max_length=2000)
    expires_at = models.DateTimeField(auto_now=False, auto_now_add=False)

    class Meta:
        ordering = ['provider']


    def __str__(self):
        '''
        retrun provider + client_id
        '''
        return 'provier: {0} | client_id: {1}'.format(self.provider, self.client_id)
