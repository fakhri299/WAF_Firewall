from django import forms

class AttackTypeForm(forms.Form):
    attack_type = forms.CharField(label='Enter OWASP Attack Type')