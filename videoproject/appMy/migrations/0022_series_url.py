# Generated by Django 4.1.5 on 2023-06-04 22:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appMy', '0021_remove_series_url'),
    ]

    operations = [
        migrations.AddField(
            model_name='series',
            name='url',
            field=models.ManyToManyField(to='appMy.seriesvideo', verbose_name='Dizi'),
        ),
    ]
