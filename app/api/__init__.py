"""The JSON API the frontend uses, under /api/v1.

Every route needs a session (auth.decorator.require_login) unless it is in PUBLIC_ENDPOINTS, and every
POST, PUT, PATCH and DELETE the session's CSRF token in an X-CSRFToken header (Flask-WTF). Errors are
{"error": "..."}; invalid requests are 422 with pydantic's list of problems.
"""

import csv
import io
from collections.abc import Callable, Iterable
from dataclasses import asdict, is_dataclass
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, make_response, request
from flask_openapi3 import APIBlueprint, Tag
from flask_wtf.csrf import CSRFError
from pydantic import BaseModel, ValidationError
from werkzeug.exceptions import HTTPException

PREFIX = "/api/v1"


def blueprint(name: str, tag: str) -> APIBlueprint:
    return APIBlueprint(name, __name__, url_prefix=PREFIX, abp_tags=[Tag(name=tag)])


def dump(model: type[BaseModel], value) -> dict:
    """A response model from the services' dataclasses, as JSON-ready data."""
    return model.model_validate(value).model_dump(mode="json")


def error(message: str, status: int):
    return jsonify({"error": message}), status


def page(model: type[BaseModel], items: list, total: int, query, **extra) -> dict:
    return dump(model, {"items": items, "total": total, "page": query.page, "per_page": query.per_page, **extra})


def paginate(items: list, query) -> tuple[list, int]:
    """One page of a list read in full (the ACME tables, the audit log's filters)."""
    start = (query.page - 1) * query.per_page
    return items[start : start + query.per_page], len(items)


def contains(needle: str, *values) -> bool:
    """The text filter of the lists: case-insensitive, in any of the values."""
    needle = needle.strip().lower()
    return not needle or any(needle in (value or "").lower() for value in values)


# Spreadsheets run cells that start with these as formulas
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list | tuple):
        value = " ".join(str(item) for item in value)
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def csv_response(filename: str, columns: list[tuple[str, Callable]], rows: Iterable) -> Response:
    """Rows as a CSV file: columns are (header, value of a row)."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([header for header, _ in columns])
    for row in rows:
        writer.writerow([_cell(value(row)) for _, value in columns])
    response = make_response(out.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def attribute(name: str) -> Callable:
    """A CSV column reading an attribute (or a dict key) of the row."""

    def read(row):
        if isinstance(row, dict):
            return row.get(name)
        if is_dataclass(row) and not isinstance(row, type):
            return asdict(row).get(name)
        return getattr(row, name, None)

    return read


def file_response(content: bytes, filename: str, content_type: str) -> Response:
    response = make_response(content)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def validation_error(e: ValidationError):
    """422 with what is wrong, without echoing the submitted values (passwords among them)."""
    response = make_response(e.json(include_url=False, include_input=False, include_context=False))
    response.headers["Content-Type"] = "application/json"
    response.status_code = 422
    return response


def is_api_request() -> bool:
    return request.path.startswith("/api/")


def register_error_handlers(app: Flask):
    """JSON errors for the API; the pages keep Flask's."""

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        if is_api_request():
            return error(f"{e.description} Reload the page and try again.", 400)
        return e

    @app.errorhandler(HTTPException)
    def http_error(e):
        if not is_api_request():
            return e
        messages = {403: "Your role does not allow this.", 404: "Not found.", 429: "Too many attempts: try again later."}
        return error(messages.get(e.code or 500, e.description or "Error"), e.code or 500)

    @app.errorhandler(requests.RequestException)
    def ca_unreachable(e):
        if not is_api_request():
            raise e
        return error(f"The CA could not be reached: {e}", 502)

    @app.errorhandler(ValidationError)
    def invalid(e):
        # Raised by a model built in a view (a request the route itself checks)
        if not is_api_request():
            raise e
        return validation_error(e)


def register(app):
    """Every API blueprint, and its JSON error handlers."""
    from app.api import acme, certificates, provisioners, session, system

    for module in (session, certificates, acme, provisioners, system):
        app.register_api(module.bp)
    register_error_handlers(app)
