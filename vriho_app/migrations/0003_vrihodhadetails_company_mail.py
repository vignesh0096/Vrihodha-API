# Generated by Django 4.2.8 on 2024-01-03 11:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vriho_app', '0002_productpulses_productrice_vrihodhadetails'),
    ]

    operations = [
        migrations.AddField(
            model_name='vrihodhadetails',
            name='company_mail',
            field=models.EmailField(blank=True, max_length=254, null=True),
        ),
    ]
