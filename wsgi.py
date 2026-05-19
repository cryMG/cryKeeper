from app import create_app


# Gunicorn imports this module and serves the already-created Flask app object.
app = create_app()
