"""The API's OpenAPI document, which the frontend's types are generated from.

    uv run python -m app.api.openapi    # writes frontend/openapi.json
"""

import json
import sys
import tempfile
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[2] / "frontend" / "openapi.json"


def document(app) -> dict:
    # Through JSON, so that the committed file and the generated document compare equal
    return json.loads(json.dumps(app.api_doc))


def main():
    from app import create_app
    from app.settings import Settings

    with tempfile.TemporaryDirectory() as data_dir:
        # The document only depends on the code: no CA, no database, nor the environment's settings
        settings = Settings.model_validate(
            {
                "data_dir": Path(data_dir),
                "testing": True,
                "secret_key": "openapi",
                "database_host": "unused",
                "sqlalchemy_database_uri": "sqlite://",
                "app_database_uri": "sqlite://",
                "ca_url": "https://unused",
                "auth_backend": "local",
            }
        )
        app = create_app(settings)
        output = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT
        output.write_text(json.dumps(document(app), indent=2, sort_keys=True) + "\n")
        print(f"Wrote {output}")


if __name__ == "__main__":
    main()
