from django.shortcuts import render

def app_info(request):
    return render(request, 'legal/app_info.html')

def privacy_policy(request):
    return render(request, 'legal/privacy_policy.html')

def terms(request):
    return render(request, 'legal/terms.html')