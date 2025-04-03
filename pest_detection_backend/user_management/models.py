from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    last_name = models.CharField(max_length=255, null=True)
    first_name = models.CharField(max_length=255, null=True)
    phone_number = models.CharField(max_length=20, null=True)
    date_of_birth = models.DateField(null=True, blank=True)
    location = models.CharField(max_length=100, blank=True)
    date_joined = models.DateField(null=True, blank=True)
    profile_picture = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.username

class UserProfileBase(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    # Remove groups and user_permissions from here, as they will be managed through signals
    class Meta:
        abstract = True

    def __str__(self):
        return self.user.username

class Client(UserProfileBase):
    pass

# @receiver(post_save, sender=Client)
# def assign_client_group(sender, instance, created, **kwargs):
#     if created:
#         instance.user.groups.add(Group.objects.get(name='Client'))

class Administrator(UserProfileBase):
    pass

# @receiver(post_save, sender=Moderateur)
# def assign_moderator_group(sender, instance, created, **kwargs):
#     if created:
#         instance.user.groups.add(Group.objects.get(name='Moderator'))
