FROM python:3.14-slim@sha256:cae66f2ef0ec51a9891263eeee7f987dacf0a9879e8aa9353d5606e0530619a5

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# The application never invokes Perl. Remove the minimal interpreter inherited
# from Debian so unrelated, currently unpatched CPAN modules are not reachable.
RUN dpkg --purge --force-remove-essential perl-base

ARG APP_VERSION
RUN test -n "${APP_VERSION}"
ENV APP_VERSION=${APP_VERSION}
LABEL org.opencontainers.image.version=${APP_VERSION}

COPY grayhaven_timetracker ./grayhaven_timetracker
COPY templates ./templates
COPY static ./static
COPY scripts ./scripts
COPY gunicorn.conf.py VERSION ./

RUN mkdir -p /app/data /app/branding \
    && chown -R app:app /app

USER app
EXPOSE 8000

CMD ["sh", "-c", "umask 077 && exec gunicorn --config gunicorn.conf.py 'grayhaven_timetracker:create_app()'"]
