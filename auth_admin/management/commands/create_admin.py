from django.core.management.base import BaseCommand
from django.db import IntegrityError
from auth_admin.models import AdminUser

class Command(BaseCommand):
    help = 'Creates a default admin user with email admin@example.com and password admin123'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            default='achraf@achraf.com',
            help='Email for the admin user',
        )
        parser.add_argument(
            '--password',
            type=str,
            default='achraf',
            help='Password for the admin user',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force creation even if user exists (will update password)',
        )

    def handle(self, *args, **options):
        email = options['email']
        password = options['password']
        force = options['force']

        try:
            # Check if user already exists
            user_exists = AdminUser.objects.filter(email=email).exists()

            if user_exists:
                if force:
                    # Update existing user
                    user = AdminUser.objects.get(email=email)
                    user.set_password(password)
                    user.is_superuser = True
                    user.is_staff = True
                    user.save()
                    self.stdout.write(self.style.SUCCESS(f'Admin user {email} updated successfully'))
                else:
                    self.stdout.write(self.style.WARNING(f'Admin user {email} already exists. Use --force to update.'))
                    return
            else:
                # Create new user
                AdminUser.objects.create_superuser(email=email, password=password)
                self.stdout.write(self.style.SUCCESS(f'Admin user {email} created successfully'))

        except IntegrityError as e:
            self.stdout.write(self.style.ERROR(f'Error creating admin user: {str(e)}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Unexpected error: {str(e)}'))