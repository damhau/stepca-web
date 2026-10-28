import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Local development only: the debugger must never be reachable in production
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1")
