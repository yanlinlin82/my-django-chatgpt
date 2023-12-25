from django.db import models
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='profile',
        verbose_name="User"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Created At"
    )
    openid = models.CharField(
        max_length=100, 
        unique=True,
        db_index=True,
        verbose_name="WeiXin OpenID"
    )
    def __str__(self):
        return f"{self.user}'s profile (created at {self.created_at}, openid: {self.openid})"

class ChatHistory(models.Model):
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        verbose_name="User Profile"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Created At"
    )

    request_body = models.TextField(null=True, blank=True)
    decrypted_request_body = models.TextField(null=True, blank=True)
    response_body = models.TextField(null=True, blank=True)

    # message information
    to_user = models.TextField(null=True, blank=True)
    from_user = models.TextField(null=True, blank=True)
    create_time = models.IntegerField(null=True, blank=True)
    message_type = models.CharField(max_length=10, null=True, blank=True)
    content = models.TextField(null=True, blank=True)
    message_id = models.CharField(max_length=100, null=True, blank=True)

    role = models.CharField(max_length=10, null=True, blank=True)

    def __str__(self):
        return f"Chat history for {self.user} at {self.created_at}: {self.from_user} -> {self.to_user} ({self.message_type}): {self.content}"
