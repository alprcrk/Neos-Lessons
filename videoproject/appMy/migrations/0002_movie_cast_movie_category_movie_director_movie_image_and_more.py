# Generated by Django 4.1.5 on 2023-05-10 22:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('appCategory', '0003_alter_subcategory_slug'),
        ('appMy', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='movie',
            name='cast',
            field=models.TextField(blank=True, max_length=500, verbose_name='Oyuncular'),
        ),
        migrations.AddField(
            model_name='movie',
            name='category',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='appCategory.category', verbose_name='Category'),
        ),
        migrations.AddField(
            model_name='movie',
            name='director',
            field=models.CharField(blank=True, max_length=50, verbose_name='Yönetmen'),
        ),
        migrations.AddField(
            model_name='movie',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to=None, verbose_name='Film Resim'),
        ),
        migrations.AddField(
            model_name='movie',
            name='slug',
            field=models.SlugField(blank=True, null=True, verbose_name='Slug Film'),
        ),
        migrations.AddField(
            model_name='movie',
            name='subcategory',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='appCategory.subcategory', verbose_name='Alt Category'),
        ),
        migrations.AddField(
            model_name='movie',
            name='text',
            field=models.TextField(blank=True, max_length=500, verbose_name='Film Açıklama'),
        ),
        migrations.AddField(
            model_name='movie',
            name='writers',
            field=models.CharField(blank=True, max_length=50, verbose_name='Senarist'),
        ),
        migrations.AddField(
            model_name='movie',
            name='yil',
            field=models.IntegerField(blank=True, null=True, verbose_name='Film Tarihi'),
        ),
    ]
