import re
from django.shortcuts import render
from .forms import AttackTypeForm
from .models import AttackType
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from ratelimit import limits
from localStoragePy import localStoragePy

localStorage = localStoragePy('owaspapp', 'http://127.0.0.1:8000')
localStorage.setItem('user_logged','True')

def detect_xss_attack(payload):
    xss_patterns = [
        r"<script\b[^>]*>(.*?)<\/script>",  # Detects <script> tags
        r"on\w+\s*=\s*\"[^\"]*\"",  # Detects event handlers like onclick=""
        r"<\w+\s+[^>][^\w\s=\"\/'>]on\w+\s=",  # Detects event handlers as attributes
        r"javascript:[^\"\']+",  # Detects JavaScript code in URLs
        # Add more patterns as needed
    ]

    for pattern in xss_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True

    return False

def detect_sql_injection(query):
    # SQL keywords and patterns to look for
    sql_keywords = ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION", "OR", "AND", "--", "#"]
    sql_pattern = r"\b(?:{})(?=\W|\b)".format("|".join(map(re.escape, sql_keywords)))

    # Check for SQL injection patterns
    if re.search(sql_pattern, query, re.IGNORECASE):
        return True
    else:

        return False

def detect_lfi_attack(payload):
    lfi_patterns = [
        r'\.\./',  # Relative path traversal
        r'\b(?:include|require|include_once|require_once)\b\s*[\'"]\.\./',
        r'\b(?:include|require|include_once|require_once)\b\s*\(\s*[\'"]\.\./'
    ]

    for pattern in lfi_patterns:
        if re.search(pattern, payload):
            return True

    return False

def detect_rfi_attack(payload):
    rfi_patterns = [
        r'\b(?:include|require|include_once|require_once)\b\s*[\'"](http|https|ftp)://',
        r'\b(?:include|require|include_once|require_once)\b\s*\(\s*[\'"](http|https|ftp)://'
    ]

    for pattern in rfi_patterns:
        if re.search(pattern, payload):
            return True

    return False



@limits(calls=15, period=10)
@login_required(login_url='login')
def attack_info(request):
    user_ip = request.META.get('REMOTE_ADDR', None)
    user_port = request.META.get('SERVER_PORT', None)

    if request.method == 'POST':
        form = AttackTypeForm(request.POST)
        if form.is_valid():
            attack_name = form.cleaned_data['attack_type']

            # Check if AttackType with the given name already exists
            attack_instance = AttackType.objects.filter(name=attack_name).first()

            if attack_instance:
                # Update existing record
                attack_instance.ip = user_ip
                attack_instance.port = user_port
                attack_instance.save()
            else:
                # Create a new AttackType instance
                attack_instance = AttackType.objects.create(
                    name=attack_name,
                    ip=user_ip,
                    port=user_port,
                )

            # Get the attack description from the dictionary
            if detect_xss_attack(attack_name):
                attack_description = "XSS Attack"
            elif detect_sql_injection(attack_name):
                attack_description = "SQL Injection"
            elif detect_lfi_attack(attack_name):
                attack_description = "Local File Inclusion (LFI) Attack"
            elif detect_rfi_attack(attack_name):
                attack_description = "Remote File Inclusion (RFI) Attack"
            else:
                attack_description = "Attack was not detected"

            # Pass attack_name to the template context
            return render(request, 'owaspapp/attack_info.html', {'attack': attack_instance, 'attack_name': attack_name, 'attack_description': attack_description})
    else:
        form = AttackTypeForm()

    return render(request, 'owaspapp/attack_form.html', {'form': form})

# views.py
from django.shortcuts import render
from .models import AttackType

def dashboard(request):
    sql_injection_count = AttackType.objects.filter(name='SQL Injection').count()
    xss_attack_count = AttackType.objects.filter(name='XSS Attack').count()
    lfi_count = AttackType.objects.filter(name='Local File Inclusion (LFI) Attack').count()
    rfi_count = AttackType.objects.filter(name='Remote File Inclusion (RFI) Attack').count()

    return render(request, 'owaspapp/dashboard.html', {
        'sql_injection_count': sql_injection_count,
        'xss_attack_count': xss_attack_count,
        'lfi_count': lfi_count,
        'rfi_count': rfi_count,
    })
