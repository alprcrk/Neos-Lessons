# Generated by Django 4.1.5 on 2023-06-04 22:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('appMy', '0018_remove_movie_video_remove_moviesvideo_video_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='series',
            name='url',
        ),
        migrations.AddField(
            model_name='series',
            name='url',
            field=models.ManyToManyField(null=True, to='appMy.seriesvideo', verbose_name='Dizi'),
        ),
    ]
