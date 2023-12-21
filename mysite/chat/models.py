from django.db import models
from django.conf import settings

class UserMessageCount(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message_count = models.IntegerField(default=0)

    def increment_message_count(self):
        self.message_count += 1
        self.save()

    def can_send_message(self):
        return self.message_count < 100
