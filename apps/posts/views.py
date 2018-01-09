from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
def index(request):
    # return HttpResponse('Hello from posts')
    return render(request, 'posts/index.html', {'title': 'latest posts'})