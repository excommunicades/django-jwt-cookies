**clone app** -> ```git clone https://github.com/excommunicades/django-jwt-cookies.git```

**open project dir** -> ```cd projec```

**create env file** -> 

```
#EMAIL
BACKEND=django.core.mail.backends.smtp.EmailBackend
HOST=smtp.gmail.com
PORT=587
USE_TLS=True
HOST_USER=YOUR_MAIL
HOST_PASSWORD=APP_PASSWORD

# PostgreSQL

POSTGRES_DB=Project
POSTGRES_USER=postgres
POSTGRES_PASSWORD=12345

# Redis
REDIS_URL=redis://redis:6379

# Django
SECRET_KEY=12345
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost,0.0.0.0

DATABASE_URL=postgres://postgres:12345@db:5432/Project
```

**to run app** -> ```docker-compose up --build```

**to stop app** -> ```docker-compose down```